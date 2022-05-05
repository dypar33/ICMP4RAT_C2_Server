import requests

class CustomProtocol:
    Header = b'\xDD'
    type = b''
    length = b''
    sequence = b''
    data = b""

    TYPE_LIST = {
        'ERROR' :  b'\x00',          
        'BEACON_REQUEST' : b'\x01',     
        'BEACON_RESPONSE' : b'\x02',    
        'SHELL_REQUEST' : b'\x03',     
        'SHELL_RESPONSE' : b'\x04',    
        'FTP_REQUEST' : b'\x05',        
        'FTP_RESPONSE' : b'\x06'        
    }

    def __init__(self, type, seq, data=b'') -> None:
        self.type = self.TYPE_LIST[type]
        self.length = len(data).to_bytes(2, byteorder="little")
        self.sequence = seq.to_bytes(4, byteorder="little")
        self.data = data

    def __bytes__(self) -> bytes:
        return self.Header + self.type + self.length + self.sequence + self.data

data = """Ping www.google.com [172.217.175.4] 32바이트 데이터 사용:
172.217.175.4의 응답: 바이트=32 시간=40ms TTL=117
172.217.175.4의 응답: 바이트=32 시간=39ms TTL=117
172.217.175.4의 응답: 바이트=32 시간=39ms TTL=117
172.217.175.4의 응답: 바이트=32 시간=40ms TTL=117

172.217.175.4에 대한 Ping 통계:
    패킷: 보냄 = 4, 받음 = 4, 손실 = 0 (0% 손실),
왕복 시간(밀리초):
    최소 = 39ms, 최대 = 40ms, 평균 = 39ms"""

#test = CustomProtocol('BEACON_REQUEST', 1, data=b'1234')
#test2 = CustomProtocol('BEACON_REQUEST', 2, data=b'5678')
test3 = CustomProtocol('SHELL_RESPONSE', 0, data=data.encode('ansi')) # ddp 데이터 구성

#response = requests.post('http://192.168.21.1:2022', data=bytes(test))
#response2 = requests.post('http://192.168.21.1:2022', data=bytes(test2))
response3 = requests.post('http://192.168.21.1:2022', data=bytes(test3)) # ddp 데이터 전송

#print(response.text)
#print(response2.text)
print(response3.text)   # 응답 값 출력