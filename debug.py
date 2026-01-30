import struct
import datetime
import os
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from enum import IntEnum
import json

# ========== ANSI цвета для консоли ==========

class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'
    
    @classmethod
    def disable(cls):
        """Отключить цвета (для записи в файл)"""
        for attr in dir(cls):
            if not attr.startswith('_') and attr.isupper():
                setattr(cls, attr, '')

# ========== Словари для расшифровки ==========

FLAP_CHANNELS = {
    0x01: "NEW_CONNECTION",
    0x02: "SNAC_DATA",
    0x03: "ERROR",
    0x04: "DISCONNECT",
    0x05: "KEEPALIVE",
}

SNAC_FAMILIES = {
    0x0001: "GENERIC",
    0x0002: "LOCATION",
    0x0003: "BUDDY",
    0x0004: "ICBM",
    0x0005: "ADVERT",
    0x0006: "INVITE",
    0x0007: "ADMIN",
    0x0008: "POPUP",
    0x0009: "PRIVACY",
    0x000A: "USER_LOOKUP",
    0x000B: "STATS",
    0x000D: "CHAT_NAV",
    0x000E: "CHAT",
    0x000F: "SEARCH",
    0x0010: "BART",
    0x0013: "SSI",
    0x0015: "ICQ_EXT",
    0x0017: "AUTH",
    0x0018: "BROADCAST",
}

# Детальное описание SNAC subtypes
SNAC_SUBTYPES = {
    # GENERIC (0x0001)
    (0x0001, 0x0001): "Error",
    (0x0001, 0x0002): "Client Ready",
    (0x0001, 0x0003): "Server Ready",
    (0x0001, 0x0004): "Service Request",
    (0x0001, 0x0005): "Redirect",
    (0x0001, 0x0006): "Rate Request",
    (0x0001, 0x0007): "Rate Response",
    (0x0001, 0x0008): "Rate Ack",
    (0x0001, 0x000E): "Self Info Request",
    (0x0001, 0x000F): "Self Info Reply",
    (0x0001, 0x0010): "Evil Notification",
    (0x0001, 0x0011): "Idle Time Set",
    (0x0001, 0x0014): "Service Versions Request",
    (0x0001, 0x0017): "Host Versions Request",
    (0x0001, 0x0018): "Host Versions Reply",
    (0x0001, 0x001E): "Set Extended Status",
    (0x0001, 0x0021): "Extended Status Reply",
    
    # LOCATION (0x0002)
    (0x0002, 0x0001): "Error",
    (0x0002, 0x0002): "Rights Request",
    (0x0002, 0x0003): "Rights Reply",
    (0x0002, 0x0004): "Set User Info",
    (0x0002, 0x0005): "User Info Request",
    (0x0002, 0x0006): "User Info Reply",
    
    # BUDDY (0x0003)
    (0x0003, 0x0001): "Error",
    (0x0003, 0x0002): "Rights Request",
    (0x0003, 0x0003): "Rights Reply",
    (0x0003, 0x0004): "Add Buddy",
    (0x0003, 0x0005): "Remove Buddy",
    (0x0003, 0x000B): "Buddy Online",
    (0x0003, 0x000C): "Buddy Offline",
    
    # ICBM (0x0004)
    (0x0004, 0x0001): "Error",
    (0x0004, 0x0002): "Params Request",
    (0x0004, 0x0003): "Params Reply",
    (0x0004, 0x0004): "Params Set",
    (0x0004, 0x0005): "Params Reply 2",
    (0x0004, 0x0006): "Outgoing Message",
    (0x0004, 0x0007): "Incoming Message",
    (0x0004, 0x000A): "Missed Calls",
    (0x0004, 0x000B): "Client Ack",
    (0x0004, 0x000C): "Server Ack",
    (0x0004, 0x0014): "Typing Notification",
    
    # PRIVACY (0x0009)
    (0x0009, 0x0002): "Rights Request",
    (0x0009, 0x0003): "Rights Reply",
    
    # SSI (0x0013)
    (0x0013, 0x0002): "Rights Request",
    (0x0013, 0x0003): "Rights Reply",
    (0x0013, 0x0004): "List Request",
    (0x0013, 0x0005): "List Request If Modified",
    (0x0013, 0x0006): "List Reply",
    (0x0013, 0x0007): "Activate",
    (0x0013, 0x0008): "Add Item",
    (0x0013, 0x0009): "Update Item",
    (0x0013, 0x000A): "Delete Item",
    (0x0013, 0x000E): "Ack",
    (0x0013, 0x0011): "Begin Transaction",
    (0x0013, 0x0012): "End Transaction",
    
    # AUTH (0x0017)
    (0x0017, 0x0002): "Login Request (MD5)",
    (0x0017, 0x0003): "Login Reply",
    (0x0017, 0x0006): "Auth Key Request",
    (0x0017, 0x0007): "Auth Key Reply",
}

TLV_TYPES = {
    0x0001: "UIN/Screenname",
    0x0002: "Message Data/Profile",
    0x0003: "Client ID String",
    0x0004: "Error URL / Auto-response",
    0x0005: "BOS Server Address",
    0x0006: "Cookie",
    0x0008: "Error Code",
    0x000C: "Distributor ID",
    0x000E: "Country",
    0x000F: "Language",
    0x0014: "Client Distrib ID",
    0x0016: "Client ID",
    0x0017: "Client Major Version",
    0x0018: "Client Minor Version",
    0x0019: "Client Point Version",
    0x001A: "Client Build Number",
    0x0025: "Password Hash (MD5)",
    0x0026: "Status",
}

ERROR_CODES = {
    0x0001: "Invalid SNAC",
    0x0002: "Rate limit exceeded",
    0x0003: "Client not logged in",
    0x0004: "Service unavailable",
    0x0005: "Service not defined",
    0x0006: "Obsolete SNAC",
    0x0007: "Not supported by host",
    0x0008: "Not supported by client",
    0x0009: "Refused by client",
    0x000A: "Reply too big",
    0x000B: "Responses lost",
    0x000C: "Request denied",
    0x000D: "Busted SNAC payload",
    0x000E: "Insufficient rights",
    0x000F: "In local permit/deny",
    0x0010: "Too evil (sender)",
    0x0011: "Too evil (receiver)",
    0x0012: "User temporarily unavailable",
    0x0013: "No match",
    0x0014: "List overflow",
    0x0015: "Request ambiguous",
    0x0016: "Queue full",
    0x0017: "Not while on AOL",
}

# ========== Вспомогательные функции ==========

def hexdump(data: bytes, prefix: str = "    ", bytes_per_line: int = 16) -> str:
    """Создаёт красивый hex-дамп данных"""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        # Добавляем пробел посередине
        if len(chunk) > 8:
            hex_part = hex_part[:23] + '  ' + hex_part[24:]
        hex_part = hex_part.ljust(49)
        
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        
        lines.append(f"{prefix}{Colors.GRAY}{i:04x}{Colors.RESET}  {Colors.CYAN}{hex_part}{Colors.RESET}  {Colors.YELLOW}|{ascii_part}|{Colors.RESET}")
    
    return '\n'.join(lines)

def format_tlv(tlv_type: int, data: bytes) -> str:
    """Форматирует TLV для отображения"""
    type_name = TLV_TYPES.get(tlv_type, "Unknown")
    
    # Пытаемся интерпретировать данные
    value_str = ""
    if len(data) == 2:
        value = struct.unpack('>H', data)[0]
        value_str = f" = 0x{value:04x} ({value})"
    elif len(data) == 4:
        value = struct.unpack('>I', data)[0]
        value_str = f" = 0x{value:08x} ({value})"
    elif len(data) <= 64:
        # Пробуем как строку
        try:
            text = data.decode('utf-8')
            if text.isprintable():
                value_str = f' = "{text}"'
        except:
            pass
    
    if not value_str and len(data) > 0:
        if len(data) <= 16:
            value_str = f" = {data.hex()}"
        else:
            value_str = f" = {data[:16].hex()}... ({len(data)} bytes)"
    
    return f"TLV(0x{tlv_type:04x}) {Colors.GREEN}{type_name}{Colors.RESET}{value_str}"

# ========== Классы для логирования ==========

@dataclass
class PacketInfo:
    """Информация о захваченном пакете"""
    timestamp: datetime.datetime
    direction: str  # 'IN' или 'OUT'
    client_addr: str
    uin: Optional[str]
    raw_data: bytes
    flap_channel: int
    snac_family: Optional[int] = None
    snac_subtype: Optional[int] = None
    snac_flags: Optional[int] = None
    snac_request_id: Optional[int] = None
    snac_data: Optional[bytes] = None
    tlvs: Optional[Dict[int, bytes]] = None

class PacketLogger:
    """Логгер пакетов с фильтрацией и выводом"""
    
    def __init__(self, 
                 enabled: bool = True,
                 show_hex: bool = True,
                 show_tlv: bool = True,
                 log_to_file: bool = True,
                 log_file: str = "packets.log",
                 filter_families: Optional[List[int]] = None,
                 filter_directions: Optional[List[str]] = None,
                 color_output: bool = True):
        
        self.enabled = enabled
        self.show_hex = show_hex
        self.show_tlv = show_tlv
        self.log_to_file = log_to_file
        self.log_file = log_file
        self.filter_families = filter_families  # None = все
        self.filter_directions = filter_directions  # ['IN'], ['OUT'], или None = оба
        self.color_output = color_output
        
        self.packets: List[PacketInfo] = []
        self.packet_count = 0
        
        if self.log_to_file:
            # Создаём/очищаем файл лога
            with open(self.log_file, 'w', encoding='utf-8') as f:
                f.write(f"=== ICQ Packet Log Started: {datetime.datetime.now()} ===\n\n")
    
    def should_log(self, packet: PacketInfo) -> bool:
        """Проверяет, нужно ли логировать пакет по фильтрам"""
        if not self.enabled:
            return False
        
        if self.filter_directions and packet.direction not in self.filter_directions:
            return False
        
        if self.filter_families and packet.snac_family:
            if packet.snac_family not in self.filter_families:
                return False
        
        return True
    
    def log_packet(self, 
                   direction: str,
                   data: bytes,
                   client_addr: str = "",
                   uin: Optional[str] = None):
        """Логирует пакет"""
        from oscar import FLAP, SNAC, TLV
        
        packet = PacketInfo(
            timestamp=datetime.datetime.now(),
            direction=direction,
            client_addr=client_addr,
            uin=uin,
            raw_data=data,
            flap_channel=0
        )
        
        # Парсим FLAP
        flap = FLAP.parse(data)
        if flap:
            packet.flap_channel = flap.channel
            
            # Парсим SNAC если это канал данных
            if flap.channel == 0x02:
                snac = SNAC.parse(flap.data)
                if snac:
                    packet.snac_family = snac.family
                    packet.snac_subtype = snac.subtype
                    packet.snac_flags = snac.flags
                    packet.snac_request_id = snac.request_id
                    packet.snac_data = snac.data
                    
                    # Парсим TLV
                    packet.tlvs = TLV.parse_all(snac.data)
        
        if not self.should_log(packet):
            return
        
        self.packet_count += 1
        self.packets.append(packet)
        
        # Формируем вывод
        output = self.format_packet(packet)
        
        # Выводим в консоль
        print(output)
        
        # Пишем в файл (без цветов)
        if self.log_to_file:
            # Временно отключаем цвета для записи
            old_colors = {}
            for attr in ['RESET', 'BOLD', 'DIM', 'RED', 'GREEN', 'YELLOW', 
                        'BLUE', 'MAGENTA', 'CYAN', 'WHITE', 'GRAY']:
                old_colors[attr] = getattr(Colors, attr)
                setattr(Colors, attr, '')
            
            plain_output = self.format_packet(packet)
            
            # Восстанавливаем цвета
            for attr, value in old_colors.items():
                setattr(Colors, attr, value)
            
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(plain_output + '\n\n')
    
    def format_packet(self, packet: PacketInfo) -> str:
        """Форматирует пакет для вывода"""
        lines = []
        
        # Заголовок
        dir_color = Colors.GREEN if packet.direction == 'IN' else Colors.BLUE
        dir_arrow = '>>>' if packet.direction == 'IN' else '<<<'
        
        header = (
            f"\n{Colors.BOLD}{'='*70}{Colors.RESET}\n"
            f"{dir_color}{Colors.BOLD}[{dir_arrow} {packet.direction}]{Colors.RESET} "
            f"#{self.packet_count} "
            f"{Colors.DIM}{packet.timestamp.strftime('%H:%M:%S.%f')[:-3]}{Colors.RESET} "
        )
        
        if packet.client_addr:
            header += f"{Colors.GRAY}from {packet.client_addr}{Colors.RESET} "
        if packet.uin:
            header += f"{Colors.YELLOW}UIN:{packet.uin}{Colors.RESET}"
        
        lines.append(header)
        
        # FLAP информация
        channel_name = FLAP_CHANNELS.get(packet.flap_channel, "UNKNOWN")
        lines.append(
            f"  {Colors.CYAN}FLAP{Colors.RESET} Channel: "
            f"{Colors.MAGENTA}0x{packet.flap_channel:02x}{Colors.RESET} "
            f"({channel_name}) | Size: {len(packet.raw_data)} bytes"
        )
        
        # SNAC информация
        if packet.snac_family is not None:
            family_name = SNAC_FAMILIES.get(packet.snac_family, "UNKNOWN")
            subtype_name = SNAC_SUBTYPES.get(
                (packet.snac_family, packet.snac_subtype), 
                "Unknown"
            )
            
            lines.append(
                f"  {Colors.CYAN}SNAC{Colors.RESET} "
                f"Family: {Colors.MAGENTA}0x{packet.snac_family:04x}{Colors.RESET} ({family_name}) | "
                f"Subtype: {Colors.MAGENTA}0x{packet.snac_subtype:04x}{Colors.RESET} ({subtype_name})"
            )
            lines.append(
                f"       Flags: 0x{packet.snac_flags:04x} | "
                f"ReqID: 0x{packet.snac_request_id:08x}"
            )
        
        # TLV информация
        if self.show_tlv and packet.tlvs:
            lines.append(f"  {Colors.CYAN}TLVs{Colors.RESET} ({len(packet.tlvs)}):")
            for tlv_type, tlv_data in packet.tlvs.items():
                lines.append(f"    • {format_tlv(tlv_type, tlv_data)}")
        
        # Специальная обработка известных типов пакетов
        special_info = self.decode_special_packet(packet)
        if special_info:
            lines.append(f"  {Colors.YELLOW}📋 Decoded:{Colors.RESET}")
            for info_line in special_info:
                lines.append(f"    {info_line}")
        
        # Hex dump
        if self.show_hex:
            lines.append(f"  {Colors.CYAN}Hex Dump:{Colors.RESET}")
            lines.append(hexdump(packet.raw_data))
        
        return '\n'.join(lines)
    
    def decode_special_packet(self, packet: PacketInfo) -> Optional[List[str]]:
        """Декодирует специфичные типы пакетов"""
        result = []
        
        if packet.snac_family == 0x0017:  # AUTH
            if packet.snac_subtype == 0x0006:  # Auth key request
                if packet.tlvs and 0x01 in packet.tlvs:
                    uin = packet.tlvs[0x01].decode('utf-8', errors='replace')
                    result.append(f"Login attempt: UIN = {uin}")
            
            elif packet.snac_subtype == 0x0003:  # Auth reply
                if packet.tlvs:
                    if 0x05 in packet.tlvs:
                        server = packet.tlvs[0x05].decode('utf-8', errors='replace')
                        result.append(f"Redirect to BOS: {server}")
                    if 0x08 in packet.tlvs:
                        error = struct.unpack('>H', packet.tlvs[0x08])[0]
                        error_desc = ERROR_CODES.get(error, "Unknown error")
                        result.append(f"Auth ERROR: 0x{error:04x} ({error_desc})")
        
        elif packet.snac_family == 0x0004:  # ICBM
            if packet.snac_subtype in (0x0006, 0x0007):  # Message
                if packet.snac_data and len(packet.snac_data) > 10:
                    try:
                        data = packet.snac_data
                        cookie = data[:8].hex()
                        channel = struct.unpack('>H', data[8:10])[0]
                        uin_len = data[10]
                        target_uin = data[11:11+uin_len].decode('utf-8')
                        
                        msg_type = "Outgoing" if packet.snac_subtype == 0x0006 else "Incoming"
                        result.append(f"{msg_type} message")
                        result.append(f"Cookie: {cookie}")
                        result.append(f"Channel: {channel}")
                        result.append(f"{'To' if packet.snac_subtype == 0x0006 else 'From'}: {target_uin}")
                    except:
                        pass
            
            elif packet.snac_subtype == 0x0014:  # Typing notification
                if packet.snac_data:
                    try:
                        data = packet.snac_data
                        # Парсим typing notification
                        offset = 8  # cookie
                        offset += 2  # channel
                        uin_len = data[offset]
                        offset += 1
                        buddy_uin = data[offset:offset+uin_len].decode('utf-8')
                        offset += uin_len
                        notification_type = struct.unpack('>H', data[offset:offset+2])[0]
                        
                        typing_states = {
                            0x0000: "Finished typing",
                            0x0001: "Text typed",
                            0x0002: "Started typing"
                        }
                        state = typing_states.get(notification_type, f"Unknown ({notification_type})")
                        result.append(f"Typing notification: {buddy_uin} - {state}")
                    except:
                        pass
        
        elif packet.snac_family == 0x0003:  # BUDDY
            if packet.snac_subtype == 0x000B:  # Online
                result.append("Buddy came ONLINE")
            elif packet.snac_subtype == 0x000C:  # Offline
                result.append("Buddy went OFFLINE")
        
        return result if result else None
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику по захваченным пакетам"""
        stats = {
            'total_packets': self.packet_count,
            'incoming': sum(1 for p in self.packets if p.direction == 'IN'),
            'outgoing': sum(1 for p in self.packets if p.direction == 'OUT'),
            'by_family': {},
            'total_bytes': sum(len(p.raw_data) for p in self.packets),
        }
        
        for p in self.packets:
            if p.snac_family:
                family_name = SNAC_FAMILIES.get(p.snac_family, f"0x{p.snac_family:04x}")
                stats['by_family'][family_name] = stats['by_family'].get(family_name, 0) + 1
        
        return stats
    
    def print_stats(self):
        """Выводит статистику"""
        stats = self.get_stats()
        print(f"\n{Colors.BOLD}{'='*50}{Colors.RESET}")
        print(f"{Colors.CYAN}Packet Statistics:{Colors.RESET}")
        print(f"  Total packets: {stats['total_packets']}")
        print(f"  Incoming (>>>): {Colors.GREEN}{stats['incoming']}{Colors.RESET}")
        print(f"  Outgoing (<<<): {Colors.BLUE}{stats['outgoing']}{Colors.RESET}")
        print(f"  Total bytes: {stats['total_bytes']}")
        print(f"\n  By SNAC Family:")
        for family, count in sorted(stats['by_family'].items()):
            print(f"    {family}: {count}")
        print(f"{Colors.BOLD}{'='*50}{Colors.RESET}\n")
    
    def save_pcap_like(self, filename: str = "packets.dump"):
        """Сохраняет пакеты в простом формате для анализа"""
        with open(filename, 'wb') as f:
            for packet in self.packets:
                # Записываем: timestamp (8), direction (1), length (4), data
                ts = int(packet.timestamp.timestamp() * 1000000)
                direction = 0 if packet.direction == 'IN' else 1
                f.write(struct.pack('>QBI', ts, direction, len(packet.raw_data)))
                f.write(packet.raw_data)
        print(f"[*] Saved {len(self.packets)} packets to {filename}")

# ========== Глобальный логгер ==========

packet_logger = PacketLogger(
    enabled=True,
    show_hex=True,
    show_tlv=True,
    log_to_file=True,
    log_file="icq_packets.log"
)

# ========== Декораторы для удобного использования ==========

def log_incoming(data: bytes, addr: str = "", uin: str = None):
    """Логирует входящий пакет"""
    packet_logger.log_packet('IN', data, addr, uin)

def log_outgoing(data: bytes, addr: str = "", uin: str = None):
    """Логирует исходящий пакет"""
    packet_logger.log_packet('OUT', data, addr, uin)