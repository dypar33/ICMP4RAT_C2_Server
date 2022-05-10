from struct import unpack

"""
DDP 프로토콜 관리 클래스
"""

class DDP:
    Header = b'\xDD'
    TYPE_LIST = {
        'ACK' : b'\x00',
        'ERROR' :  b'\x01',          
        'BEACON_REQUEST' : b'\x02',
        'SHELL_REQUEST' : b'\x03',     
        'SHELL_RESPONSE' : b'\x04',    
        'FTP_REQUEST' : b'\x05',        
        'FTP_RESPONSE' : b'\x06'        
    }

    ERROR_TABLE = {
        'FILE_ERROR' : b'\x01'
    }
    
    def _get_type(self, type_num):
        for k, v in self.TYPE_LIST.items():
            if v == type_num.to_bytes(1, byteorder="little"):
                return k

    @classmethod
    def parsing(cls, raw_data) -> dict:
        result = {}
        result['header'] = hex(raw_data[0])
        result['type'] = cls._get_type(cls, raw_data[1])
        result['length'] = unpack('<L', raw_data[2:6])[0]
        result['sequence'] = unpack('<L', raw_data[6:10])[0]
        result['data'] = raw_data[10:11+result['length']]

        return result

    @classmethod
    def raw(cls, p_type : str, seq, data=b'') -> bytes:
        if type(p_type) == str:
            p_type = cls.TYPE_LIST[p_type.upper()]

        length = len(data).to_bytes(4, byteorder="little")
        seq = seq.to_bytes(4, byteorder="little")

        return cls.Header + p_type  + length + seq + data 