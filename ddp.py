from enum import Enum
from struct import unpack

class DDPParseError(Exception):
    pass

class TYPE_CODE(Enum):
    ACK = 0
    ERROR = 1
    BEACON_REQUEST = 2
    SHELL_REQUEST = 3
    SHELL_RESPONSE = 4
    FTP_REQUEST = 5
    FTP_RESPONSE = 6


class ERROR_CODE(Enum):
    UNKNOWN_ERROR = 0x0
    INVALID_HEADER_ERROR = 0x1
    ACCESS_BLOCKED = 0x2
    DATA_DECODING_ERROR = 0x3
    FILE_ERROR = 0x10
    SENDING_FILE_ERROR = 0x11
    RECEIVING_FILE_ERROR = 0x12
    SEQ_ERROR = 0x20
    SEQ_TASK_RUNNING = 0x21


class DDP:
    HEADER = b'\xDD'
    
    @classmethod
    def parse(cls, raw_data : bytes) -> dict:
        if len(raw_data) < 10:
            raise DDPParseError('invalid body data / {}'.format(raw_data))

        try:
            parsed_data = {}
            parsed_data['header'] = hex(raw_data[0])
            parsed_data['type'] = TYPE_CODE(raw_data[1]).name
            parsed_data['length'] = unpack('<L', raw_data[2:6])[0]
            parsed_data['sequence'] = unpack('<L', raw_data[6:10])[0]
            parsed_data['data'] = raw_data[10:11+parsed_data['length']]
        except Exception as e:
            raise DDPParseError('{0} / {1}'.format(e, raw_data))

        return parsed_data

    @classmethod
    def raw(cls, p_type, seq, data=b'') -> bytes:
        if isinstance(p_type, str):
            p_type = getattr(TYPE_CODE, p_type.upper()).value
        
        p_type = p_type.to_bytes(1, byteorder='little')

        length = len(data).to_bytes(4, byteorder="little")
        seq = seq.to_bytes(4, byteorder="little")

        return cls.HEADER + p_type  + length + seq + data
