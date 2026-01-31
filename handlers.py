import struct
import os
import time
from oscar import SNAC, TLV, SNACFamily
from database import db
from typing import TYPE_CHECKING, List, Dict

if TYPE_CHECKING:
    from server import ClientConnection


class SNACHandler:
    def __init__(self, connection: 'ClientConnection'):
        self.conn = connection
    
    def handle(self, snac: SNAC) -> List[SNAC]:
        handler_name = f"handle_{snac.family:04x}_{snac.subtype:04x}"
        handler = getattr(self, handler_name, None)
        
        if handler:
            result = handler(snac)
            return result if isinstance(result, list) else [result] if result else []
        else:
            print(f"[!] Unknown SNAC: 0x{snac.family:04x}/0x{snac.subtype:04x}")
            return []
    
    # ==================== GENERIC (0x0001) ====================
    
    def handle_0001_0002(self, snac: SNAC) -> List[SNAC]:
        print(f"[GENERIC] Client Ready: {self.conn.uin}")
        return []
    
    def handle_0001_0004(self, snac: SNAC) -> List[SNAC]:
        if len(snac.data) >= 2:
            family = struct.unpack('>H', snac.data[:2])[0]
            print(f"[GENERIC] Service request: 0x{family:04x}")
        return []
    
    def handle_0001_0006(self, snac: SNAC) -> List[SNAC]:
        print(f"[GENERIC] Rate limits request")
        
        data = struct.pack('>H', 5)
        
        for i in range(1, 6):
            data += struct.pack('>H', i)
            data += struct.pack('>I', 80)
            data += struct.pack('>I', 2500)
            data += struct.pack('>I', 2000)
            data += struct.pack('>I', 1500)
            data += struct.pack('>I', 1000)
            data += struct.pack('>I', 2500)
            data += struct.pack('>I', 6000)
            data += struct.pack('>I', 0)
            data += struct.pack('>B', 0)
        
        data += struct.pack('>HH', 1, 1)
        data += struct.pack('>HH', 0x0001, 0x0001)
        
        return [SNAC(SNACFamily.GENERIC, 0x07, 0, snac.request_id, data)]
    
    def handle_0001_0008(self, snac: SNAC) -> List[SNAC]:
        print(f"[GENERIC] Rate limits ack")
        return []
    
    def handle_0001_000e(self, snac: SNAC) -> List[SNAC]:
        print(f"[GENERIC] Self info request: {self.conn.uin}")
        
        uin = self.conn.uin or "0"
        uin_bytes = uin.encode('utf-8')
        
        data = struct.pack('B', len(uin_bytes)) + uin_bytes
        data += struct.pack('>H', 0)
        data += struct.pack('>H', 4)
        
        data += TLV.pack_uint16(0x01, 0x0010)
        data += TLV.pack_uint32(0x03, int(time.time()))
        data += TLV.pack_uint32(0x05, int(time.time()))
        data += TLV.pack_uint16(0x0F, 0)
        
        return [SNAC(SNACFamily.GENERIC, 0x0f, 0, snac.request_id, data)]
    
    def handle_0001_0011(self, snac: SNAC) -> List[SNAC]:
        if len(snac.data) >= 4:
            idle_time = struct.unpack('>I', snac.data[0:4])[0]
            print(f"[GENERIC] Idle time: {idle_time}s")
        return []
    
    def handle_0001_0017(self, snac: SNAC) -> List[SNAC]:
        print(f"[GENERIC] Host versions request")
        
        data = b''
        offset = 0
        while offset + 2 <= len(snac.data):
            family = struct.unpack('>H', snac.data[offset:offset+2])[0]
            offset += 2
            data += struct.pack('>HH', family, 1)
        
        return [SNAC(SNACFamily.GENERIC, 0x18, 0, snac.request_id, data)]
    
    def handle_0001_001e(self, snac: SNAC) -> List[SNAC]:
        """Set Extended Status - включая X-Status"""
        print(f"[GENERIC] Set extended status: {self.conn.uin}")
        
        tlvs = TLV.parse_all(snac.data)
        
        status_flags = self.conn.status_flags
        status = self.conn.status
        x_status_data = b''
        dc_info = b''
        capabilities = b''
        
        # TLV 0x06 - Status
        if 0x06 in tlvs:
            status_data = tlvs[0x06]
            if len(status_data) >= 4:
                status_flags = struct.unpack('>H', status_data[0:2])[0]
                status = struct.unpack('>H', status_data[2:4])[0]
                print(f"[STATUS] flags=0x{status_flags:04x}, status=0x{status:04x}")
        
        # TLV 0x08 - Status code
        if 0x08 in tlvs:
            print(f"[STATUS] Status code: {tlvs[0x08].hex()}")
        
        # TLV 0x0C - DC Info
        if 0x0C in tlvs:
            dc_info = tlvs[0x0C]
            print(f"[STATUS] DC Info: {len(dc_info)} bytes")
        
        # TLV 0x0D - Capabilities
        if 0x0D in tlvs:
            capabilities = tlvs[0x0D]
            print(f"[STATUS] Capabilities: {len(capabilities)} bytes")
        
        # TLV 0x1D - X-Status (Extended Status)
        if 0x1D in tlvs:
            x_status_data = tlvs[0x1D]
            print(f"[STATUS] X-Status ({len(x_status_data)} bytes): {x_status_data.hex()}")
        
        # TLV 0x1F - Unknown
        if 0x1F in tlvs:
            print(f"[STATUS] TLV 0x1F: {tlvs[0x1F].hex()}")
        
        import asyncio
        asyncio.create_task(
            self.conn.server.set_user_status(
                self.conn,
                status_flags,
                status,
                x_status_data=x_status_data,
                capabilities=capabilities,
                dc_info=dc_info
            )
        )
        
        return []
    
    # ==================== LOCATION (0x0002) ====================
    
    def handle_0002_0002(self, snac: SNAC) -> List[SNAC]:
        print(f"[LOCATION] Rights request")
        
        data = TLV.pack_uint16(0x01, 0x0400)
        data += TLV.pack_uint16(0x02, 0x0800)
        data += TLV.pack_uint16(0x03, 0x000A)
        data += TLV.pack_uint16(0x04, 0x0800)
        
        return [SNAC(SNACFamily.LOCATION, 0x03, 0, snac.request_id, data)]
    
    def handle_0002_0004(self, snac: SNAC) -> List[SNAC]:
        """Set User Info - сохраняем capabilities"""
        print(f"[LOCATION] Set user info: {self.conn.uin}")
        
        tlvs = TLV.parse_all(snac.data)
        
        # TLV 0x05 - Capabilities
        if 0x05 in tlvs:
            self.conn.capabilities = tlvs[0x05]
            print(f"[LOCATION] Capabilities: {len(self.conn.capabilities)} bytes")
        
        # TLV 0x02 - Profile
        if 0x02 in tlvs:
            print(f"[LOCATION] Profile set")
        
        return []
    
    def handle_0002_0005(self, snac: SNAC) -> List[SNAC]:
        if len(snac.data) < 3:
            return []
        
        uin_len = snac.data[2]
        target = snac.data[3:3+uin_len].decode('utf-8', errors='replace')
        print(f"[LOCATION] User info request: {target}")
        
        data = struct.pack('B', len(target)) + target.encode('utf-8')
        data += struct.pack('>HH', 0, 0)
        
        return [SNAC(SNACFamily.LOCATION, 0x06, 0, snac.request_id, data)]
    
    # ==================== BUDDY (0x0003) ====================
    
    def handle_0003_0002(self, snac: SNAC) -> List[SNAC]:
        print(f"[BUDDY] Rights request")
        
        data = TLV.pack_uint16(0x01, 200)
        data += TLV.pack_uint16(0x02, 200)
        data += TLV.pack_uint16(0x03, 200)
        
        return [SNAC(SNACFamily.BUDDY, 0x03, 0, snac.request_id, data)]
    
    def handle_0003_0004(self, snac: SNAC) -> List[SNAC]:
        print(f"[BUDDY] Add temp buddy")
        return []
    
    def handle_0003_0005(self, snac: SNAC) -> List[SNAC]:
        print(f"[BUDDY] Remove temp buddy")
        return []
    
    # ==================== ICBM (0x0004) ====================
    
    def handle_0004_0002(self, snac: SNAC) -> List[SNAC]:
        print(f"[ICBM] Params request")
        return self._icbm_params(snac.request_id)
    
    def handle_0004_0004(self, snac: SNAC) -> List[SNAC]:
        print(f"[ICBM] Set params")
        return self._icbm_params(snac.request_id)
    
    def _icbm_params(self, req_id: int) -> List[SNAC]:
        data = struct.pack('>H', 0)
        data += struct.pack('>I', 0x0B)
        data += struct.pack('>H', 8000)
        data += struct.pack('>H', 999)
        data += struct.pack('>H', 999)
        data += struct.pack('>I', 0)
        data += struct.pack('>H', 0)
        
        return [SNAC(SNACFamily.ICBM, 0x05, 0, req_id, data)]
    
    def handle_0004_0006(self, snac: SNAC) -> List[SNAC]:
        data = snac.data
        
        cookie = data[0:8]
        channel = struct.unpack('>H', data[8:10])[0]
        uin_len = data[10]
        recipient = data[11:11+uin_len].decode('utf-8', errors='replace')
        
        tlvs = TLV.parse_all(data[11+uin_len:])
        
        message = ""
        if 0x02 in tlvs:
            message = self._extract_message(tlvs[0x02])
        
        print(f"[MSG] {self.conn.uin} -> {recipient}: {message}")
        
        self.conn.server.deliver_message(
            self.conn.uin, recipient, message, cookie, tlvs.get(0x02, b'')
        )
        
        if 0x03 in tlvs:
            ack = cookie + struct.pack('>H', channel)
            ack += struct.pack('B', len(recipient)) + recipient.encode('utf-8')
            return [SNAC(SNACFamily.ICBM, 0x0c, 0, snac.request_id, ack)]
        
        return []
    
    def handle_0004_0014(self, snac: SNAC) -> List[SNAC]:
        if len(snac.data) < 13:
            return []
        
        uin_len = snac.data[10]
        buddy = snac.data[11:11+uin_len].decode('utf-8', errors='replace')
        notification = struct.unpack('>H', snac.data[11+uin_len:13+uin_len])[0] if len(snac.data) >= 13+uin_len else 0
        
        typing_states = {0: "finished", 1: "typed", 2: "typing"}
        print(f"[TYPING] {self.conn.uin} -> {buddy}: {typing_states.get(notification, notification)}")
        
        recipient = self.conn.server.bos_connections.get(buddy)
        if recipient:
            import asyncio
            asyncio.create_task(self._forward_typing(recipient, self.conn.uin, notification))
        
        return []
    
    async def _forward_typing(self, recipient, from_uin: str, notification: int):
        cookie = os.urandom(8)
        uin_bytes = from_uin.encode('utf-8')
        
        data = cookie
        data += struct.pack('>H', 1)
        data += struct.pack('B', len(uin_bytes)) + uin_bytes
        data += struct.pack('>H', notification)
        
        await recipient.send_snac(SNAC(SNACFamily.ICBM, 0x14, 0, 0, data))
    
    def _extract_message(self, msg_data: bytes) -> str:
        try:
            offset = 0
            while offset + 4 < len(msg_data):
                frag_id = msg_data[offset]
                frag_len = struct.unpack('>H', msg_data[offset+2:offset+4])[0]
                offset += 4
                
                if frag_id == 0x01 and offset + frag_len <= len(msg_data):
                    charset = struct.unpack('>H', msg_data[offset:offset+2])[0]
                    text = msg_data[offset+4:offset+frag_len]
                    
                    if charset == 0x0002:
                        return text.decode('utf-16be', errors='replace')
                    elif charset == 0x0003:
                        return text.decode('cp1251', errors='replace')
                    else:
                        return text.decode('utf-8', errors='replace')
                
                offset += frag_len
            return ""
        except:
            return ""
    
    # ==================== PRIVACY (0x0009) ====================
    
    def handle_0009_0002(self, snac: SNAC) -> List[SNAC]:
        print(f"[PRIVACY] Rights request")
        
        data = TLV.pack_uint16(0x01, 200)
        data += TLV.pack_uint16(0x02, 200)
        
        return [SNAC(SNACFamily.PRIVACY, 0x03, 0, snac.request_id, data)]
    
    def handle_0009_0004(self, snac: SNAC) -> List[SNAC]:
        return []
    
    def handle_0009_0005(self, snac: SNAC) -> List[SNAC]:
        return []
    
    # ==================== SSI (0x0013) ====================
    
    def handle_0013_0002(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] Rights request")
        
        data = b''
        for t in [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0C, 0x0D]:
            data += TLV.pack_uint16(t, 200)
        
        return [SNAC(SNACFamily.SSI, 0x03, 0, snac.request_id, data)]
    
    def handle_0013_0004(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] Full list request")
        return self._send_contact_list(snac)
    
    def handle_0013_0005(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] List request (if modified)")
        return self._send_contact_list(snac)
    
    def _send_contact_list(self, snac: SNAC) -> List[SNAC]:
        contacts = db.get_contacts(self.conn.uin) if self.conn.uin else []
        print(f"[SSI] Sending {len(contacts)} contacts for {self.conn.uin}")
        
        items_data = b''
        item_count = 0
        
        for i, contact_uin in enumerate(contacts):
            item_id = i + 1
            name = contact_uin.encode('utf-8')
            
            buddy_tlvs = b''
            contact_user = db.get_user(contact_uin)
            if contact_user and contact_user.nickname:
                buddy_tlvs += TLV.pack(0x0131, contact_user.nickname.encode('utf-8'))
            
            item = struct.pack('>H', len(name)) + name
            item += struct.pack('>HHH', 1, item_id, 0x0000)
            item += struct.pack('>H', len(buddy_tlvs)) + buddy_tlvs
            
            items_data += item
            item_count += 1
        
        master_tlv = TLV.pack(0x00C8, struct.pack('>H', 1))
        master = struct.pack('>HHHH', 0, 0, 0, 0x0001)
        master += struct.pack('>H', len(master_tlv)) + master_tlv
        items_data += master
        item_count += 1
        
        group_name = b'General'
        if contacts:
            buddy_ids = b''.join(struct.pack('>H', i+1) for i in range(len(contacts)))
            group_tlv = TLV.pack(0x00C8, buddy_ids)
        else:
            group_tlv = b''
        
        group = struct.pack('>H', len(group_name)) + group_name
        group += struct.pack('>HHH', 1, 0, 0x0001)
        group += struct.pack('>H', len(group_tlv)) + group_tlv
        items_data += group
        item_count += 1
        
        priv_tlv = TLV.pack(0x00CA, struct.pack('>B', 0x04))
        priv = struct.pack('>HHHH', 0, 0, 0xFFFF, 0x0004)
        priv += struct.pack('>H', len(priv_tlv)) + priv_tlv
        items_data += priv
        item_count += 1
        
        data = struct.pack('>BH', 0, item_count)
        data += items_data
        data += struct.pack('>I', int(time.time()))
        
        return [SNAC(SNACFamily.SSI, 0x06, 0, snac.request_id, data)]
    
    def handle_0013_0007(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] Activated: {self.conn.uin}")
        
        import asyncio
        asyncio.create_task(self._on_ssi_activated())
        
        return []
    
    async def _on_ssi_activated(self):
        import asyncio
        await asyncio.sleep(0.3)
        await self.conn.server.send_contact_statuses(self.conn)
        await self.conn.server.broadcast_status(self.conn.uin, offline=False)
    
    def handle_0013_0008(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] Add item")
        
        items = self._parse_ssi_items(snac.data)
        results = []
        
        for item in items:
            print(f"[SSI] Adding: name='{item['name']}', type=0x{item['type']:04x}")
            
            if item['type'] == 0x0000 and item['name']:
                if db.add_contact(self.conn.uin, item['name']):
                    print(f"[SSI] Contact saved: {self.conn.uin} -> {item['name']}")
            
            results.append(0x0000)
        
        return [SNAC(SNACFamily.SSI, 0x0E, 0, snac.request_id,
                     b''.join(struct.pack('>H', r) for r in results))]
    
    def handle_0013_0009(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] Update item")
        
        items = self._parse_ssi_items(snac.data)
        results = [0x0000] * len(items)
        
        return [SNAC(SNACFamily.SSI, 0x0E, 0, snac.request_id,
                     b''.join(struct.pack('>H', r) for r in results))]
    
    def handle_0013_000a(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] Delete item")
        
        items = self._parse_ssi_items(snac.data)
        results = []
        
        for item in items:
            print(f"[SSI] Deleting: name='{item['name']}', type=0x{item['type']:04x}")
            
            if item['type'] == 0x0000 and item['name']:
                if db.remove_contact(self.conn.uin, item['name']):
                    print(f"[SSI] Contact removed: {self.conn.uin} -> {item['name']}")
            
            results.append(0x0000)
        
        return [SNAC(SNACFamily.SSI, 0x0E, 0, snac.request_id,
                     b''.join(struct.pack('>H', r) for r in results))]
    
    def _parse_ssi_items(self, data: bytes) -> List[dict]:
        items = []
        offset = 0
        
        while offset + 10 <= len(data):
            try:
                name_len = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                
                if offset + name_len > len(data):
                    break
                
                name = data[offset:offset+name_len].decode('utf-8', errors='replace')
                offset += name_len
                
                if offset + 6 > len(data):
                    break
                
                group_id, item_id, item_type = struct.unpack('>HHH', data[offset:offset+6])
                offset += 6
                
                if offset + 2 > len(data):
                    break
                
                tlv_len = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2 + tlv_len
                
                items.append({
                    'name': name,
                    'group_id': group_id,
                    'item_id': item_id,
                    'type': item_type
                })
            except:
                break
        
        return items
    
    def handle_0013_0011(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] Edit begin")
        return []
    
    def handle_0013_0012(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] Edit end")
        return []
    
    def handle_0013_0014(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] Auth request")
        return []
    
    def handle_0013_0018(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] You were added")
        return []
    
    def handle_0013_001a(self, snac: SNAC) -> List[SNAC]:
        print(f"[SSI] Auth reply")
        return []
    
    # ==================== ICQ_EXT (0x0015) ====================
    
    def handle_0015_0002(self, snac: SNAC) -> List[SNAC]:
        tlvs = TLV.parse_all(snac.data)
        if 0x01 not in tlvs:
            print(f"[ICQ_EXT] No TLV 0x01")
            return []
        
        data = tlvs[0x01]
        print(f"[ICQ_EXT] TLV data ({len(data)}): {data.hex()}")
        
        if len(data) < 10:
            return []
        
        data_len = struct.unpack('<H', data[0:2])[0]
        owner_uin = struct.unpack('<I', data[2:6])[0]
        req_type = struct.unpack('<H', data[6:8])[0]
        req_seq = struct.unpack('<H', data[8:10])[0]
        req_data = data[10:]
        
        print(f"[ICQ_EXT] owner={owner_uin}, type=0x{req_type:04x}, seq={req_seq}")
        
        if req_type == 0x07D0:
            return self._handle_meta_request(snac, owner_uin, req_seq, req_data)
        
        elif req_type == 0x003C:
            print(f"[ICQ_EXT] Offline messages request")
            return self._icq_response(snac, owner_uin, req_seq, 0x0042, b'\x00')
        
        elif req_type == 0x003E:
            return []
        
        else:
            print(f"[ICQ_EXT] Unknown type: 0x{req_type:04x}")
            return []
    
    def _handle_meta_request(self, snac: SNAC, owner_uin: int, seq: int, data: bytes) -> List[SNAC]:
        if len(data) < 2:
            return []
        
        subtype = struct.unpack('<H', data[0:2])[0]
        subdata = data[2:]
        
        print(f"[ICQ_EXT] META subtype=0x{subtype:04x}, data: {subdata.hex() if subdata else 'empty'}")
        
        if subtype == 0x0569:
            return self._handle_wp_uin_search(snac, owner_uin, seq, subdata)
        
        elif subtype == 0x051F:
            return self._handle_wp_short_search(snac, owner_uin, seq, subdata)
        
        elif subtype == 0x0533:
            return self._handle_wp_short_search(snac, owner_uin, seq, subdata)
        
        elif subtype == 0x04D0:
            return self._handle_info_request(snac, owner_uin, seq, subdata, full=True)
        
        elif subtype == 0x04BA:
            return self._handle_info_request(snac, owner_uin, seq, subdata, full=False)
        
        elif subtype == 0x042E:
            print(f"[ICQ_EXT] User updating info")
            inner = struct.pack('<HB', 0x0C3F, 0x0A)
            return self._icq_response(snac, owner_uin, seq, 0x07DA, inner)
        
        else:
            print(f"[ICQ_EXT] Unknown META: 0x{subtype:04x}")
            return self._send_search_end(snac, owner_uin, seq, found=False)
    
    def _handle_wp_uin_search(self, snac: SNAC, owner_uin: int, seq: int, data: bytes) -> List[SNAC]:
        print(f"[ICQ_EXT] WP_UIN_SEARCH: {data.hex() if data else 'empty'}")
        
        target_uin = None
        
        if len(data) >= 6:
            block_len = struct.unpack('<H', data[0:2])[0]
            if block_len >= 4:
                target_uin = struct.unpack('<I', data[2:6])[0]
        elif len(data) >= 4:
            target_uin = struct.unpack('<I', data[0:4])[0]
        
        print(f"[ICQ_EXT] Searching UIN: {target_uin}")
        
        if target_uin and target_uin > 0:
            user = db.get_user(str(target_uin))
            if user:
                print(f"[ICQ_EXT] Found: {target_uin} ({user.nickname})")
                return self._send_search_results(snac, owner_uin, seq, [user])
        
        return self._send_search_end(snac, owner_uin, seq, found=False)
    
    def _handle_wp_short_search(self, snac: SNAC, owner_uin: int, seq: int, data: bytes) -> List[SNAC]:
        print(f"[ICQ_EXT] WP_SHORT_SEARCH: {data.hex() if data else 'empty'}")
        
        search_params = self._parse_le_tlvs(data)
        
        nickname = ""
        email = ""
        
        if 0x0154 in search_params:
            nickname = search_params[0x0154].decode('utf-8', errors='replace').rstrip('\x00')
        if 0x015E in search_params:
            email = search_params[0x015E].decode('utf-8', errors='replace').rstrip('\x00')
        
        print(f"[ICQ_EXT] Search: nick='{nickname}', email='{email}'")
        
        results = []
        for user in db.list_users():
            if nickname and nickname.lower() in user.nickname.lower():
                results.append(user)
            elif email and email.lower() in user.email.lower():
                results.append(user)
        
        if results:
            return self._send_search_results(snac, owner_uin, seq, results)
        return self._send_search_end(snac, owner_uin, seq, found=False)
    
    def _handle_info_request(self, snac: SNAC, owner_uin: int, seq: int,
                              data: bytes, full: bool) -> List[SNAC]:
        target_uin = None
        if len(data) >= 4:
            target_uin = struct.unpack('<I', data[0:4])[0]
        
        print(f"[ICQ_EXT] INFO_REQUEST for UIN: {target_uin}")
        
        user = db.get_user(str(target_uin)) if target_uin else None
        
        subtype = 0x00C8 if full else 0x0104
        inner = struct.pack('<H', subtype)
        
        if user:
            inner += struct.pack('<B', 0x0A)
            
            nick = (user.nickname or f"User{target_uin}").encode('utf-8') + b'\x00'
            inner += struct.pack('<H', len(nick)) + nick
            
            first = (user.first_name or "").encode('utf-8') + b'\x00'
            inner += struct.pack('<H', len(first)) + first
            
            last = (user.last_name or "").encode('utf-8') + b'\x00'
            inner += struct.pack('<H', len(last)) + last
            
            email = (user.email or f"{target_uin}@icq.com").encode('utf-8') + b'\x00'
            inner += struct.pack('<H', len(email)) + email
            
            inner += struct.pack('<BIB', 0, 0, user.gender)
        else:
            inner += struct.pack('<B', 0x32)
        
        return self._icq_response(snac, owner_uin, seq, 0x07DA, inner)
    
    def _send_search_results(self, snac: SNAC, owner_uin: int, seq: int,
                              users: list) -> List[SNAC]:
        results = []
        
        for user in users:
            inner = struct.pack('<H', 0x01A4)
            inner += struct.pack('<B', 0x0A)
            inner += struct.pack('<I', int(user.uin))
            
            nick = (user.nickname or f"User{user.uin}").encode('utf-8') + b'\x00'
            inner += struct.pack('<H', len(nick)) + nick
            
            first = (user.first_name or "").encode('utf-8') + b'\x00'
            inner += struct.pack('<H', len(first)) + first
            
            last = (user.last_name or "").encode('utf-8') + b'\x00'
            inner += struct.pack('<H', len(last)) + last
            
            email = (user.email or f"{user.uin}@icq.com").encode('utf-8') + b'\x00'
            inner += struct.pack('<H', len(email)) + email
            
            inner += struct.pack('<BHB', 0, 0, user.gender)
            inner += struct.pack('<H', 0)
            
            results.extend(self._icq_response(snac, owner_uin, seq, 0x07DA, inner))
            print(f"[ICQ_EXT] Result: {user.uin} ({user.nickname})")
        
        results.extend(self._send_search_end(snac, owner_uin, seq, found=True, count=len(users)))
        
        return results
    
    def _send_search_end(self, snac: SNAC, owner_uin: int, seq: int,
                          found: bool, count: int = 0) -> List[SNAC]:
        inner = struct.pack('<H', 0x01AE)
        inner += struct.pack('<B', 0x0A if found else 0x32)
        inner += struct.pack('<I', count)
        inner += struct.pack('<I', 0)
        
        print(f"[ICQ_EXT] Search end: found={found}, count={count}")
        return self._icq_response(snac, owner_uin, seq, 0x07DA, inner)
    
    def _parse_le_tlvs(self, data: bytes) -> Dict[int, bytes]:
        result = {}
        offset = 0
        
        while offset + 4 <= len(data):
            try:
                tlv_type = struct.unpack('<H', data[offset:offset+2])[0]
                tlv_len = struct.unpack('<H', data[offset+2:offset+4])[0]
                offset += 4
                
                if offset + tlv_len <= len(data):
                    result[tlv_type] = data[offset:offset+tlv_len]
                    offset += tlv_len
                else:
                    break
            except:
                break
        
        return result
    
    def _icq_response(self, snac: SNAC, owner_uin: int, seq: int,
                      resp_type: int, data: bytes) -> List[SNAC]:
        content = struct.pack('<I', owner_uin)
        content += struct.pack('<H', resp_type)
        content += struct.pack('<H', seq)
        content += data
        
        tlv_data = struct.pack('<H', len(content)) + content
        response = TLV.pack(0x01, tlv_data)
        
        return [SNAC(0x0015, 0x03, 0, snac.request_id, response)]