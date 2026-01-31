import struct
from dataclasses import dataclass
from typing import Optional, Dict
from enum import IntEnum


class FLAPChannel(IntEnum):
    NEW_CONNECTION = 0x01
    SNAC_DATA = 0x02
    ERROR = 0x03
    DISCONNECT = 0x04
    KEEPALIVE = 0x05


class SNACFamily(IntEnum):
    GENERIC = 0x0001
    LOCATION = 0x0002
    BUDDY = 0x0003
    ICBM = 0x0004
    PRIVACY = 0x0009
    SSI = 0x0013
    ICQ_EXT = 0x0015
    AUTH = 0x0017


@dataclass
class FLAP:
    channel: int
    sequence: int
    data: bytes
    
    HEADER_SIZE = 6
    MARKER = 0x2A
    
    @classmethod
    def parse(cls, data: bytes) -> Optional['FLAP']:
        if len(data) < cls.HEADER_SIZE:
            return None
        if data[0] != cls.MARKER:
            return None
        
        channel, sequence, length = struct.unpack('>BHH', data[1:6])
        
        if len(data) < cls.HEADER_SIZE + length:
            return None
        
        payload = data[6:6+length]
        return cls(channel, sequence, payload)
    
    def pack(self) -> bytes:
        header = struct.pack('>BBHH',
            self.MARKER,
            self.channel,
            self.sequence,
            len(self.data)
        )
        return header + self.data
    
    @classmethod
    def total_size(cls, data: bytes) -> int:
        if len(data) < cls.HEADER_SIZE:
            return 0
        length = struct.unpack('>H', data[4:6])[0]
        return cls.HEADER_SIZE + length


@dataclass
class SNAC:
    family: int
    subtype: int
    flags: int
    request_id: int
    data: bytes
    
    HEADER_SIZE = 10
    
    @classmethod
    def parse(cls, data: bytes) -> Optional['SNAC']:
        if len(data) < cls.HEADER_SIZE:
            return None
        family, subtype, flags, request_id = struct.unpack('>HHHI', data[:10])
        return cls(family, subtype, flags, request_id, data[10:])
    
    def pack(self) -> bytes:
        header = struct.pack('>HHHI',
            self.family,
            self.subtype,
            self.flags,
            self.request_id
        )
        return header + self.data


class TLV:
    @staticmethod
    def pack(tlv_type: int, data: bytes) -> bytes:
        return struct.pack('>HH', tlv_type, len(data)) + data
    
    @staticmethod
    def pack_string(tlv_type: int, s: str) -> bytes:
        data = s.encode('utf-8')
        return TLV.pack(tlv_type, data)
    
    @staticmethod
    def pack_uint16(tlv_type: int, value: int) -> bytes:
        return TLV.pack(tlv_type, struct.pack('>H', value))
    
    @staticmethod
    def pack_uint32(tlv_type: int, value: int) -> bytes:
        return TLV.pack(tlv_type, struct.pack('>I', value))
    
    @staticmethod
    def parse_all(data: bytes) -> Dict[int, bytes]:
        result = {}
        offset = 0
        while offset + 4 <= len(data):
            tlv_type, length = struct.unpack('>HH', data[offset:offset+4])
            offset += 4
            if offset + length <= len(data):
                result[tlv_type] = data[offset:offset+length]
                offset += length
            else:
                break
        return result