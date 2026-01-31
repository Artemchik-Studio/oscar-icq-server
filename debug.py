import struct
import datetime
from dataclasses import dataclass
from typing import Optional, List, Dict


class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'


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
    0x0009: "PRIVACY",
    0x0013: "SSI",
    0x0015: "ICQ_EXT",
    0x0017: "AUTH",
}


def hexdump(data: bytes, prefix: str = "    ") -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(48)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{prefix}{i:04x}  {hex_part}  |{ascii_part}|")
    return '\n'.join(lines)


@dataclass
class PacketInfo:
    timestamp: datetime.datetime
    direction: str
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
    def __init__(self,
                 enabled: bool = True,
                 show_hex: bool = True,
                 log_to_file: bool = True,
                 log_file: str = "packets.log"):
        
        self.enabled = enabled
        self.show_hex = show_hex
        self.log_to_file = log_to_file
        self.log_file = log_file
        self.packets: List[PacketInfo] = []
        self.packet_count = 0
        
        if self.log_to_file:
            try:
                with open(self.log_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== ICQ Packet Log: {datetime.datetime.now()} ===\n\n")
            except:
                self.log_to_file = False
    
    def log_packet(self, direction: str, data: bytes,
                   client_addr: str = "", uin: Optional[str] = None):
        if not self.enabled:
            return
        
        from oscar import FLAP, SNAC, TLV
        
        packet = PacketInfo(
            timestamp=datetime.datetime.now(),
            direction=direction,
            client_addr=client_addr,
            uin=uin,
            raw_data=data,
            flap_channel=0
        )
        
        flap = FLAP.parse(data)
        if flap:
            packet.flap_channel = flap.channel
            
            if flap.channel == 0x02:
                snac = SNAC.parse(flap.data)
                if snac:
                    packet.snac_family = snac.family
                    packet.snac_subtype = snac.subtype
                    packet.snac_flags = snac.flags
                    packet.snac_request_id = snac.request_id
                    packet.snac_data = snac.data
                    try:
                        packet.tlvs = TLV.parse_all(snac.data)
                    except:
                        pass
        
        self.packet_count += 1
        self.packets.append(packet)
        
        output = self.format_packet(packet)
        print(output)
        
        if self.log_to_file:
            try:
                plain = self.format_packet_plain(packet)
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(plain + '\n\n')
            except:
                pass
    
    def format_packet(self, p: PacketInfo) -> str:
        dir_color = Colors.GREEN if p.direction == 'IN' else Colors.BLUE
        arrow = '>>>' if p.direction == 'IN' else '<<<'
        
        lines = [
            f"\n{'='*70}",
            f"{dir_color}[{arrow} {p.direction}]{Colors.RESET} #{self.packet_count} "
            f"{p.timestamp.strftime('%H:%M:%S.%f')[:-3]} "
            f"from {p.client_addr} UIN:{p.uin or '?'}"
        ]
        
        channel_name = FLAP_CHANNELS.get(p.flap_channel, "UNKNOWN")
        lines.append(f"  FLAP Channel: 0x{p.flap_channel:02x} ({channel_name}) | {len(p.raw_data)} bytes")
        
        if p.snac_family is not None:
            family_name = SNAC_FAMILIES.get(p.snac_family, "UNKNOWN")
            lines.append(
                f"  SNAC: {Colors.CYAN}{family_name}{Colors.RESET} "
                f"(0x{p.snac_family:04x}/0x{p.snac_subtype:04x}) "
                f"ReqID=0x{p.snac_request_id:08x}"
            )
        
        if self.show_hex:
            lines.append(f"  Hex:")
            lines.append(hexdump(p.raw_data))
        
        return '\n'.join(lines)
    
    def format_packet_plain(self, p: PacketInfo) -> str:
        arrow = '>>>' if p.direction == 'IN' else '<<<'
        
        lines = [
            f"{'='*70}",
            f"[{arrow} {p.direction}] #{self.packet_count} "
            f"{p.timestamp.strftime('%H:%M:%S.%f')[:-3]} "
            f"from {p.client_addr} UIN:{p.uin or '?'}"
        ]
        
        channel_name = FLAP_CHANNELS.get(p.flap_channel, "UNKNOWN")
        lines.append(f"  FLAP: 0x{p.flap_channel:02x} ({channel_name}) | {len(p.raw_data)} bytes")
        
        if p.snac_family is not None:
            family_name = SNAC_FAMILIES.get(p.snac_family, "UNKNOWN")
            lines.append(f"  SNAC: {family_name} (0x{p.snac_family:04x}/0x{p.snac_subtype:04x})")
        
        if self.show_hex:
            lines.append(hexdump(p.raw_data))
        
        return '\n'.join(lines)
    
    def print_stats(self):
        incoming = sum(1 for p in self.packets if p.direction == 'IN')
        outgoing = sum(1 for p in self.packets if p.direction == 'OUT')
        print(f"\n{'='*50}")
        print(f"Packets: {self.packet_count} (IN: {incoming}, OUT: {outgoing})")
        print(f"{'='*50}\n")


packet_logger = PacketLogger(enabled=True, show_hex=True, log_to_file=True)


def log_incoming(data: bytes, addr: str = "", uin: str = None):
    packet_logger.log_packet('IN', data, addr, uin)


def log_outgoing(data: bytes, addr: str = "", uin: str = None):
    packet_logger.log_packet('OUT', data, addr, uin)