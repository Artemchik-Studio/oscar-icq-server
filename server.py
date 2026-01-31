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


class ICQStatus:
    ONLINE = 0x0000
    AWAY = 0x0001
    DND = 0x0002
    NA = 0x0004
    BUSY = 0x0010
    FREE_FOR_CHAT = 0x0020
    INVISIBLE = 0x0100
    
    NAMES = {
        0x0000: "Online",
        0x0001: "Away",
        0x0002: "Do Not Disturb",
        0x0004: "Not Available",
        0x0010: "Occupied",
        0x0020: "Free for Chat",
        0x0100: "Invisible",
    }


class AuthError:
    INVALID_UIN = 0x0001
    INVALID_PASSWORD = 0x0004


@dataclass
class ClientConnection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    server: 'ICQServer'
    uin: Optional[str] = None
    user: Optional[User] = None
    sequence: int = 0
    handler: Optional[SNACHandler] = None
    is_bos: bool = False
    addr: str = ""
    
    # Status
    status_flags: int = 0x0000
    status: int = ICQStatus.ONLINE
    
    # X-Status (extended status) - TLV 0x1D data
    x_status_data: bytes = field(default_factory=bytes)
    
    # Capabilities - TLV 0x0D data
    capabilities: bytes = field(default_factory=bytes)
    
    # DC Info - TLV 0x0C data
    dc_info: bytes = field(default_factory=bytes)
    
    def __post_init__(self):
        self.handler = SNACHandler(self)
        info = self.writer.get_extra_info('peername')
        self.addr = f"{info[0]}:{info[1]}" if info else "?"
    
    def next_sequence(self) -> int:
        self.sequence = (self.sequence + 1) % 0x10000
        return self.sequence
    
    async def send_flap(self, channel: int, data: bytes):
        flap = FLAP(channel, self.next_sequence(), data)
        raw = flap.pack()
        try:
            log_outgoing(raw, self.addr, self.uin)
        except:
            pass
        self.writer.write(raw)
        await self.writer.drain()
    
    async def send_snac(self, snac: SNAC):
        await self.send_flap(FLAPChannel.SNAC_DATA, snac.pack())


class ICQServer:
    ROAST_KEY = bytes([
        0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92,
        0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C
    ])
    
    def __init__(self):
        self.bos_connections: Dict[str, ClientConnection] = {}
        self.pending_cookies: Dict[bytes, str] = {}
    
    def decode_password(self, roasted: bytes) -> str:
        pw = bytes(roasted[i] ^ self.ROAST_KEY[i % 16] for i in range(len(roasted)))
        return pw.decode('utf-8', errors='replace').rstrip('\x00')
    
    async def handle_auth_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"\n[AUTH] Connection: {addr}")
        
        conn = ClientConnection(reader, writer, self, is_bos=False)
        
        try:
            await conn.send_flap(FLAPChannel.NEW_CONNECTION, b'\x00\x00\x00\x01')
            await self._process(conn)
        except Exception as e:
            print(f"[AUTH] Error: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
    
    async def handle_bos_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        print(f"\n[BOS] Connection: {addr}")
        
        conn = ClientConnection(reader, writer, self, is_bos=True)
        
        try:
            await conn.send_flap(FLAPChannel.NEW_CONNECTION, b'\x00\x00\x00\x01')
            await self._process(conn)
        except Exception as e:
            print(f"[BOS] Error: {e}")
        finally:
            if conn.uin:
                self.bos_connections.pop(conn.uin, None)
                try:
                    await self.broadcast_status(conn.uin, offline=True)
                except:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            print(f"[BOS] Disconnected: {addr}")
    
    async def _process(self, conn: ClientConnection):
        buf = b''
        while True:
            try:
                data = await conn.reader.read(4096)
                if not data:
                    break
                
                buf += data
                
                while True:
                    size = FLAP.total_size(buf)
                    if size == 0 or len(buf) < size:
                        break
                    
                    raw = buf[:size]
                    buf = buf[size:]
                    
                    try:
                        log_incoming(raw, conn.addr, conn.uin)
                    except:
                        pass
                    
                    flap = FLAP.parse(raw)
                    if flap:
                        await self._handle_flap(conn, flap)
            except ConnectionResetError:
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                break
    
    async def _handle_flap(self, conn: ClientConnection, flap: FLAP):
        if flap.channel == FLAPChannel.NEW_CONNECTION:
            if len(flap.data) < 4:
                return
            
            tlvs = TLV.parse_all(flap.data[4:])
            
            if 0x06 in tlvs:
                cookie = tlvs[0x06]
                if cookie in self.pending_cookies:
                    uin = self.pending_cookies.pop(cookie)
                    conn.uin = uin
                    conn.user = db.get_user(uin)
                    self.bos_connections[uin] = conn
                    print(f"[BOS] Authenticated: {uin}")
                    await self._send_host_online(conn)
            
            elif 0x01 in tlvs:
                await self._handle_login(conn, tlvs)
        
        elif flap.channel == FLAPChannel.SNAC_DATA:
            snac = SNAC.parse(flap.data)
            if snac:
                for resp in conn.handler.handle(snac):
                    await conn.send_snac(resp)
        
        elif flap.channel == FLAPChannel.KEEPALIVE:
            pass
    
    async def _handle_login(self, conn: ClientConnection, tlvs):
        uin = tlvs.get(0x01, b'').decode('utf-8', errors='replace')
        roasted = tlvs.get(0x02, b'')
        password = self.decode_password(roasted) if roasted else ""
        
        print(f"[AUTH] Login: {uin}")
        
        if not db.user_exists(uin):
            print(f"[AUTH] User not found: {uin}")
            await self._send_auth_error(conn, AuthError.INVALID_UIN, uin)
            return
        
        user = db.authenticate(uin, password)
        if not user:
            print(f"[AUTH] Invalid password: {uin}")
            await self._send_auth_error(conn, AuthError.INVALID_PASSWORD, uin)
            return
        
        print(f"[AUTH] Success: {uin}")
        
        conn.uin = uin
        conn.user = user
        
        cookie = os.urandom(256)
        self.pending_cookies[cookie] = uin
        
        bos_addr = f"{config.BOS_HOST}:{config.BOS_PORT}"
        
        resp = TLV.pack_string(0x01, uin)
        resp += TLV.pack_string(0x05, bos_addr)
        resp += TLV.pack(0x06, cookie)
        resp += TLV.pack_string(0x11, user.email)
        
        await conn.send_flap(FLAPChannel.DISCONNECT, resp)
    
    async def _send_auth_error(self, conn: ClientConnection, code: int, uin: str):
        resp = TLV.pack_string(0x01, uin)
        resp += TLV.pack(0x04, b"Authentication failed")
        resp += TLV.pack(0x08, struct.pack('>H', code))
        await conn.send_flap(FLAPChannel.DISCONNECT, resp)
    
    async def _send_host_online(self, conn: ClientConnection):
        families = [0x0001, 0x0002, 0x0003, 0x0004, 0x0009, 0x0013, 0x0015]
        data = b''.join(struct.pack('>H', f) for f in families)
        await conn.send_snac(SNAC(SNACFamily.GENERIC, 0x03, 0, 0, data))
    
    async def set_user_status(self, conn: ClientConnection, status_flags: int, status: int,
                               x_status_data: bytes = b'', capabilities: bytes = b'',
                               dc_info: bytes = b''):
        """Устанавливает статус пользователя и рассылает обновление"""
        conn.status_flags = status_flags
        conn.status = status
        
        if x_status_data:
            conn.x_status_data = x_status_data
        if capabilities:
            conn.capabilities = capabilities
        if dc_info:
            conn.dc_info = dc_info
        
        status_name = ICQStatus.NAMES.get(status, f"0x{status:04x}")
        print(f"[STATUS] {conn.uin} -> {status_name}")
        if x_status_data:
            print(f"[STATUS] X-Status data: {x_status_data.hex()}")
        
        await self.broadcast_status(conn.uin, offline=False)
    
    async def send_contact_statuses(self, conn: ClientConnection):
        if not conn.uin:
            return
        
        await asyncio.sleep(0.3)
        
        contacts = db.get_contacts(conn.uin)
        print(f"[STATUS] Sending to {conn.uin}: {contacts}")
        
        for contact in contacts:
            if contact in self.bos_connections:
                await self._send_buddy_status(conn, contact, online=True)
    
    async def _send_buddy_status(self, conn: ClientConnection, buddy_uin: str, online: bool):
        """Отправляет статус контакта с X-Status"""
        try:
            buddy_conn = self.bos_connections.get(buddy_uin) if online else None
            
            uin_bytes = buddy_uin.encode('utf-8')
            data = struct.pack('B', len(uin_bytes)) + uin_bytes
            data += struct.pack('>H', 0)  # warning level
            
            if online and buddy_conn:
                tlvs = b''
                tlv_count = 0
                
                # TLV 0x0001 - User class
                tlvs += TLV.pack_uint16(0x0001, 0x0010)
                tlv_count += 1
                
                # TLV 0x0003 - Signon time
                tlvs += TLV.pack_uint32(0x0003, int(time.time()))
                tlv_count += 1
                
                # TLV 0x0004 - Idle time
                tlvs += TLV.pack_uint16(0x0004, 0)
                tlv_count += 1
                
                # TLV 0x0006 - ICQ Status (flags + status)
                status_data = struct.pack('>HH', buddy_conn.status_flags, buddy_conn.status)
                tlvs += TLV.pack(0x0006, status_data)
                tlv_count += 1
                
                # TLV 0x000C - DC Info
                if buddy_conn.dc_info:
                    tlvs += TLV.pack(0x000C, buddy_conn.dc_info)
                else:
                    dc = struct.pack('>IIHIHHHHHHI', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                    tlvs += TLV.pack(0x000C, dc)
                tlv_count += 1
                
                # TLV 0x000D - Capabilities (важно для X-Status!)
                if buddy_conn.capabilities:
                    tlvs += TLV.pack(0x000D, buddy_conn.capabilities)
                    tlv_count += 1
                else:
                    # Базовые capabilities
                    caps = bytes.fromhex('094613494C7F11D18222444553540000')
                    tlvs += TLV.pack(0x000D, caps)
                    tlv_count += 1
                
                # TLV 0x000F - Online time
                tlvs += TLV.pack_uint32(0x000F, 0)
                tlv_count += 1
                
                # TLV 0x001D - X-Status (Extended Status) - КЛЮЧЕВОЙ ДЛЯ QIP СТАТУСОВ!
                if buddy_conn.x_status_data:
                    tlvs += TLV.pack(0x001D, buddy_conn.x_status_data)
                    tlv_count += 1
                
                data += struct.pack('>H', tlv_count)
                data += tlvs
                
                await conn.send_snac(SNAC(SNACFamily.BUDDY, 0x0B, 0, 0, data))
                
                status_name = ICQStatus.NAMES.get(buddy_conn.status, "Unknown")
                print(f"[STATUS] >> {buddy_uin} ({status_name}) -> {conn.uin}")
            else:
                data += struct.pack('>H', 0)
                await conn.send_snac(SNAC(SNACFamily.BUDDY, 0x0C, 0, 0, data))
                print(f"[STATUS] >> {buddy_uin} OFFLINE -> {conn.uin}")
                
        except Exception as e:
            print(f"[STATUS] Error: {e}")
            import traceback
            traceback.print_exc()
    
    async def broadcast_status(self, uin: str, offline: bool = False):
        contacts = db.get_contacts(uin)
        
        status_str = "OFFLINE" if offline else "ONLINE"
        print(f"[STATUS] Broadcasting {uin} {status_str} to {len(contacts)} contacts")
        
        for contact in contacts:
            conn = self.bos_connections.get(contact)
            if conn:
                await self._send_buddy_status(conn, uin, online=not offline)
    
    def deliver_message(self, from_uin: str, to_uin: str, message: str,
                       cookie: bytes, original_tlv02: bytes = b''):
        recipient = self.bos_connections.get(to_uin)
        if recipient:
            asyncio.create_task(
                self._send_message(recipient, from_uin, message, cookie, original_tlv02)
            )
        else:
            print(f"[MSG] {to_uin} offline, saving")
            db.save_offline_message(from_uin, to_uin, message)
    
    async def _send_message(self, recipient, from_uin: str, message: str,
                           cookie: bytes, original_tlv02: bytes):
        uin_bytes = from_uin.encode('utf-8')
        
        data = cookie
        data += struct.pack('>H', 1)
        data += struct.pack('B', len(uin_bytes)) + uin_bytes
        data += struct.pack('>HH', 0, 4)
        
        data += TLV.pack_uint16(0x01, 0x0010)
        data += TLV.pack_uint32(0x03, int(time.time()))
        data += TLV.pack_uint16(0x06, 0)
        data += TLV.pack_uint16(0x0F, 0)
        
        if original_tlv02:
            data += TLV.pack(0x02, original_tlv02)
        else:
            msg_bytes = message.encode('utf-16be')
            frag = struct.pack('>BBH', 0x05, 0x01, 4) + struct.pack('>HH', 0x0101, 0x0001)
            frag += struct.pack('>BBH', 0x01, 0x01, len(msg_bytes) + 4)
            frag += struct.pack('>HH', 0x0002, 0xFFFF) + msg_bytes
            data += TLV.pack(0x02, frag)
        
        await recipient.send_snac(SNAC(SNACFamily.ICBM, 0x07, 0, 0, data))
        print(f"[MSG] Delivered: {from_uin} -> {recipient.uin}")


async def main():
    server = ICQServer()
    stats = db.get_stats()
    
    print("\n" + "=" * 50)
    print("ICQ/OSCAR Server")
    print("=" * 50)
    print(f"  Auth: {config.HOST}:{config.AUTH_PORT}")
    print(f"  BOS:  {config.HOST}:{config.BOS_PORT}")
    print(f"  Users: {stats['users']}")
    print("=" * 50)
    
    if stats['users'] == 0:
        print("\nNo users! Run: python database.py init\n")
    
    auth = await asyncio.start_server(
        server.handle_auth_client, config.HOST, config.AUTH_PORT
    )
    bos = await asyncio.start_server(
        server.handle_bos_client, config.HOST, config.BOS_PORT
    )
    
    print(f"[*] Server running...\n")
    
    try:
        async with auth, bos:
            await asyncio.gather(
                auth.serve_forever(),
                bos.serve_forever()
            )
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")


if __name__ == '__main__':
    try:
        asyncio.run(main()) 
    except KeyboardInterrupt:
        print("\n[*] Stopped")