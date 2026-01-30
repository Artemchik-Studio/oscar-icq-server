# server.py - Полная версия с проверкой авторизации

import asyncio
import struct
import time
import os
from dataclasses import dataclass, field
from typing import Dict, Optional

from oscar import FLAP, SNAC, TLV, FLAPChannel, SNACFamily
from handlers import SNACHandler
from database import db, User
from debug import packet_logger, log_incoming, log_outgoing
import config


# Коды ошибок авторизации
class AuthError:
    INVALID_UIN = 0x0001
    SERVICE_DOWN = 0x0002
    OTHER_ERROR = 0x0003
    INVALID_PASSWORD = 0x0004
    MISMATCH_PASSWORD = 0x0005
    BAD_INPUT = 0x0006
    NOT_REGISTERED = 0x0007
    DELETED_UIN = 0x0008
    EXPIRED = 0x0009
    NO_ACCESS = 0x000A
    SUSPENDED = 0x0012
    RATE_LIMITED = 0x0018
    OLD_VERSION = 0x001B


@dataclass
class ClientConnection:
    """Представляет подключение клиента"""
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    server: 'ICQServer'
    uin: Optional[str] = None
    user: Optional[User] = None
    sequence: int = 0
    auth_key: bytes = field(default_factory=bytes)
    pending_uin: str = ""
    handler: Optional['SNACHandler'] = None
    is_bos: bool = False
    addr: str = ""
    
    def __post_init__(self):
        self.handler = SNACHandler(self)
        addr_info = self.writer.get_extra_info('peername')
        self.addr = f"{addr_info[0]}:{addr_info[1]}" if addr_info else "unknown"
    
    def next_sequence(self) -> int:
        self.sequence = (self.sequence + 1) % 0x10000
        return self.sequence
    
    async def send_flap(self, channel: int, data: bytes):
        flap = FLAP(channel, self.next_sequence(), data)
        raw_data = flap.pack()
        log_outgoing(raw_data, self.addr, self.uin) # type: ignore
        self.writer.write(raw_data)
        await self.writer.drain()
    
    async def send_snac(self, snac: SNAC):
        await self.send_flap(FLAPChannel.SNAC_DATA, snac.pack())


class ICQServer:
    """Главный сервер ICQ"""
    
    ROAST_KEY = bytes([
        0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92,
        0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C
    ])
    
    def __init__(self):
        self.auth_connections: Dict[str, ClientConnection] = {}
        self.bos_connections: Dict[str, ClientConnection] = {}
        self.pending_cookies: Dict[bytes, str] = {}
    
    def decode_roasted_password(self, roasted: bytes) -> str:
        """Расшифровывает XOR-закодированный пароль"""
        password = bytes(
            roasted[i] ^ self.ROAST_KEY[i % len(self.ROAST_KEY)]
            for i in range(len(roasted))
        )
        return password.decode('utf-8', errors='replace').rstrip('\x00')
    
    # ==================== Обработчики подключений ====================
    
    async def handle_auth_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        print(f"\n[AUTH] Новое подключение: {addr}")
        
        conn = ClientConnection(reader, writer, self, is_bos=False)
        
        try:
            await conn.send_flap(FLAPChannel.NEW_CONNECTION, b'\x00\x00\x00\x01')
            await self.process_client(conn)
        except ConnectionResetError:
            print(f"[AUTH] Connection reset: {addr}")
        except Exception as e:
            print(f"[AUTH] Ошибка: {e}")
            import traceback
            traceback.print_exc()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            print(f"[AUTH] Отключение: {addr}")
    
    async def handle_bos_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        print(f"\n[BOS] Новое подключение: {addr}")
        
        conn = ClientConnection(reader, writer, self, is_bos=True)
        
        try:
            await conn.send_flap(FLAPChannel.NEW_CONNECTION, b'\x00\x00\x00\x01')
            await self.process_client(conn)
        except ConnectionResetError:
            print(f"[BOS] Connection reset: {addr}")
        except Exception as e:
            print(f"[BOS] Ошибка: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if conn.uin:
                self.bos_connections.pop(conn.uin, None)
                await self.broadcast_status(conn.uin, offline=True)
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            print(f"[BOS] 🔌 Отключение: {addr}")
    
    async def process_client(self, conn: ClientConnection):
        buffer = b''
        
        while True:
            try:
                data = await conn.reader.read(4096)
                if not data:
                    break
                
                buffer += data
                
                while True:
                    size = FLAP.total_size(buffer)
                    if size == 0 or len(buffer) < size:
                        break
                    
                    raw_packet = buffer[:size]
                    buffer = buffer[size:]
                    
                    log_incoming(raw_packet, conn.addr, conn.uin) # type: ignore
                    
                    flap = FLAP.parse(raw_packet)
                    if flap:
                        await self.handle_flap(conn, flap)
            except ConnectionResetError:
                break
            except Exception as e:
                print(f"[!] Error processing client: {e}")
                break
    
    async def handle_flap(self, conn: ClientConnection, flap: FLAP):
        if flap.channel == FLAPChannel.NEW_CONNECTION:
            if len(flap.data) < 4:
                return
            
            protocol_version = struct.unpack('>I', flap.data[:4])[0]
            tlvs = TLV.parse_all(flap.data[4:])
            
            if 0x06 in tlvs:
                # Подключение к BOS с cookie
                cookie = tlvs[0x06]
                if cookie in self.pending_cookies:
                    uin = self.pending_cookies.pop(cookie)
                    conn.uin = uin
                    conn.user = db.get_user(uin)
                    self.bos_connections[uin] = conn
                    print(f"[BOS] Авторизован по cookie: UIN={uin}")
                    
                    await self.send_host_online(conn)
                    await self.broadcast_status(uin, offline=False)
                else:
                    print(f"[BOS] Неизвестный cookie!")
                    await self.send_auth_error(conn, AuthError.OTHER_ERROR, "")
            
            elif 0x01 in tlvs:
                # OLD-STYLE авторизация
                await self.handle_old_style_login(conn, tlvs)
        
        elif flap.channel == FLAPChannel.SNAC_DATA:
            snac = SNAC.parse(flap.data)
            if snac:
                responses = conn.handler.handle(snac) # type: ignore
                for response in responses:
                    await conn.send_snac(response)
        
        elif flap.channel == FLAPChannel.DISCONNECT:
            print(f"[*] Клиент запросил отключение")
        
        elif flap.channel == 0x05:
            pass
    
    # ==================== Авторизация ====================
    
    async def handle_old_style_login(self, conn: ClientConnection, tlvs: Dict[int, bytes]):
        """Обработка OLD-STYLE авторизации с проверкой в БД"""
        
        # TLV 0x01 - UIN
        uin = tlvs.get(0x01, b'').decode('utf-8', errors='replace')
        
        # TLV 0x02 - Roasted password
        roasted_password = tlvs.get(0x02, b'')
        password = self.decode_roasted_password(roasted_password) if roasted_password else ""
        
        # TLV 0x03 - Client name
        client_name = tlvs.get(0x03, b'').decode('utf-8', errors='replace')
        
        print(f"[AUTH] Login attempt:")
        print(f"       UIN: {uin}")
        print(f"       Password: {'*' * len(password)}")
        print(f"       Client: {client_name}")
        
        # ========== ПРОВЕРКА В БАЗЕ ДАННЫХ ==========
        
        # 1. Проверяем что пользователь существует
        if not db.user_exists(uin):
            print(f"[AUTH] User not found: {uin}")
            await self.send_auth_error(conn, AuthError.INVALID_UIN, uin)
            return
        
        # 2. Проверяем пароль
        user = db.authenticate(uin, password)
        if not user:
            print(f"[AUTH] Invalid password for: {uin}")
            await self.send_auth_error(conn, AuthError.INVALID_PASSWORD, uin)
            return
        
        # ========== УСПЕШНАЯ АВТОРИЗАЦИЯ ==========
        
        print(f"[AUTH] Authentication successful: {uin} ({user.nickname})")
        
        conn.uin = uin
        conn.user = user
        
        # Генерируем cookie для BOS
        cookie = os.urandom(256)
        self.pending_cookies[cookie] = uin
        
        # Формируем ответ
        bos_address = f"{config.BOS_HOST}:{config.BOS_PORT}"
        
        response_data = b''
        response_data += TLV.pack_string(0x01, uin)
        response_data += TLV.pack_string(0x05, bos_address)
        response_data += TLV.pack(0x06, cookie)
        response_data += TLV.pack_string(0x11, user.email)
        
        print(f"[AUTH] Redirecting to BOS: {bos_address}")
        
        await conn.send_flap(FLAPChannel.DISCONNECT, response_data)
    
    async def send_auth_error(self, conn: ClientConnection, error_code: int, uin: str):
        """Отправляет ошибку авторизации"""
        
        error_messages = {
            AuthError.INVALID_UIN: "Invalid UIN",
            AuthError.INVALID_PASSWORD: "Incorrect password",
            AuthError.NOT_REGISTERED: "UIN not registered",
            AuthError.SUSPENDED: "Account suspended",
            AuthError.RATE_LIMITED: "Too many login attempts",
        }
        
        error_url = error_messages.get(error_code, "Authentication failed")
        
        response_data = b''
        response_data += TLV.pack_string(0x01, uin)
        response_data += TLV.pack(0x04, error_url.encode('utf-8'))  # Error URL/message
        response_data += TLV.pack(0x08, struct.pack('>H', error_code))  # Error code
        
        print(f"[AUTH] Sending error: {error_code} - {error_url}")
        
        await conn.send_flap(FLAPChannel.DISCONNECT, response_data)
    
    # ==================== BOS ====================
    
    async def send_host_online(self, conn: ClientConnection):
        families = [
            0x0001, 0x0002, 0x0003, 0x0004, 
            0x0009, 0x0013, 0x0015,
        ]
        data = b''.join(struct.pack('>H', f) for f in families)
        await conn.send_snac(SNAC(SNACFamily.GENERIC, 0x03, 0, 0, data))
    
    # ==================== Статусы ====================
    
    async def send_contact_statuses(self, conn: ClientConnection):
        if not conn.user:
            return
        
        await asyncio.sleep(0.3)
        
        contacts = db.get_contacts(conn.uin) # type: ignore
        print(f"[STATUS] Sending contact statuses to {conn.uin} ({len(contacts)} contacts)")
        
        for contact_uin in contacts:
            if contact_uin in self.bos_connections:
                await self._send_buddy_online(conn, contact_uin)
    
    async def _send_buddy_online(self, conn: ClientConnection, buddy_uin: str):
        uin_bytes = buddy_uin.encode('utf-8')
        
        data = struct.pack('B', len(uin_bytes)) + uin_bytes
        data += struct.pack('>H', 0)
        data += struct.pack('>H', 4)
        
        data += TLV.pack_uint16(0x01, 0x0010)
        data += TLV.pack_uint32(0x03, int(time.time()))
        data += TLV.pack_uint16(0x06, 0x0000)
        data += TLV.pack_uint16(0x0F, 0)
        
        await conn.send_snac(SNAC(SNACFamily.BUDDY, 0x0B, 0, 0, data))
        print(f"[STATUS] Sent {buddy_uin} ONLINE to {conn.uin}")
    
    async def broadcast_status(self, uin: str, offline: bool = False):
        contacts = db.get_contacts(uin)
        if not contacts:
            return
        
        status_str = "OFFLINE" if offline else "ONLINE"
        print(f"[STATUS] Broadcasting: {uin} is now {status_str}")
        
        for contact_uin in contacts:
            contact_conn = self.bos_connections.get(contact_uin)
            if contact_conn:
                uin_bytes = uin.encode('utf-8')
                data = struct.pack('B', len(uin_bytes)) + uin_bytes
                data += struct.pack('>H', 0)
                
                if not offline:
                    data += struct.pack('>H', 4)
                    data += TLV.pack_uint16(0x01, 0x0010)
                    data += TLV.pack_uint32(0x03, int(time.time()))
                    data += TLV.pack_uint16(0x06, 0x0000)
                    data += TLV.pack_uint16(0x0F, 0)
                    await contact_conn.send_snac(SNAC(SNACFamily.BUDDY, 0x0B, 0, 0, data))
                else:
                    data += struct.pack('>H', 0)
                    await contact_conn.send_snac(SNAC(SNACFamily.BUDDY, 0x0C, 0, 0, data))
    
    # ==================== Сообщения ====================
    
    def deliver_message(self, from_uin: str, to_uin: str, message: str,
                       cookie: bytes, original_tlv02: bytes = b''):
        recipient = self.bos_connections.get(to_uin)
        if recipient:
            asyncio.create_task(
                self._send_message(recipient, from_uin, message, cookie, original_tlv02)
            )
        else:
            # Сохраняем offline сообщение
            print(f"[MSG] {to_uin} offline, saving message")
            db.save_offline_message(from_uin, to_uin, message)
    
    async def _send_message(self, recipient: ClientConnection, from_uin: str,
                           message: str, cookie: bytes, original_tlv02: bytes):
        
        data = cookie
        data += struct.pack('>H', 1)
        
        uin_bytes = from_uin.encode('utf-8')
        data += struct.pack('B', len(uin_bytes)) + uin_bytes
        
        data += struct.pack('>H', 0)
        data += struct.pack('>H', 4)
        
        data += TLV.pack_uint16(0x01, 0x0010)
        data += TLV.pack_uint32(0x03, int(time.time()))
        data += TLV.pack_uint16(0x06, 0x0000)
        data += TLV.pack_uint16(0x0F, 0)
        
        if original_tlv02:
            data += TLV.pack(0x02, original_tlv02)
        else:
            msg_bytes = message.encode('utf-16be')
            
            fragment = struct.pack('>BBH', 0x05, 0x01, 0x0004)
            fragment += struct.pack('>HH', 0x0101, 0x0001)
            
            fragment += struct.pack('>BBH', 0x01, 0x01, len(msg_bytes) + 4)
            fragment += struct.pack('>HH', 0x0002, 0xFFFF)
            fragment += msg_bytes
            
            data += TLV.pack(0x02, fragment)
        
        await recipient.send_snac(SNAC(SNACFamily.ICBM, 0x07, 0, 0, data))
        print(f"[MSG] Delivered: {from_uin} -> {recipient.uin}")


# ==================== Main ====================

async def main():
    server = ICQServer()
    
    # Статистика БД
    stats = db.get_stats()
    
    print("\n" + "=" * 60)
    print("🔷 ICQ/OSCAR Server")
    print("=" * 60)
    print(f"  Auth server: {config.HOST}:{config.AUTH_PORT}")
    print(f"  BOS server:  {config.HOST}:{config.BOS_PORT}")
    print(f"  BOS address: {config.BOS_HOST}:{config.BOS_PORT}")
    print("-" * 60)
    print(f"  📊 Database: {db.db_path}")
    print(f"     Users: {stats['users']}")
    print(f"     Contacts: {stats['contacts']}")
    print(f"     Pending messages: {stats['pending_offline_messages']}")
    print("=" * 60)
    
    if stats['users'] == 0:
        print("\n⚠️  No users in database!")
        print("   Run: python database.py init")
        print("   Or:  python database.py add <uin> <password> [nickname]")
        print()
    
    auth_server = await asyncio.start_server(
        server.handle_auth_client,
        config.HOST,
        config.AUTH_PORT
    )
    print(f"[*] 🚀 Auth server started on {config.HOST}:{config.AUTH_PORT}")
    
    bos_server = await asyncio.start_server(
        server.handle_bos_client,
        config.HOST,
        config.BOS_PORT
    )
    print(f"[*] 🚀 BOS server started on {config.HOST}:{config.BOS_PORT}")
    
    print(f"\n[*] 📝 Packet log: {packet_logger.log_file}")
    print(f"[*] Press Ctrl+C to stop\n")
    
    try:
        async with auth_server, bos_server:
            await asyncio.gather(
                auth_server.serve_forever(),
                bos_server.serve_forever()
            )
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        packet_logger.print_stats()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass