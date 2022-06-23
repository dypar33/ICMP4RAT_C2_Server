from setting import *
import logging
import os

logger = logging.getLogger(LOGGER_NAME)

"""
    자주 쓰이는 함수들 모음
"""

class SEQFileMixin():
    # save splited file
    def _save_seq_file(self, seq_name : str, seq_num : int, data : bytes):
        file_name = TMP_FILE_PATH + seq_name + TMP_FILE_EXTENSION.format(seq_num)

        if os.path.isfile(file_name):
            raise SEQNumError('SEQNumError : seq num has overlap..!')

        try:
            with open(file_name, 'wb') as f:
                f.write(data)
                pass
        except:
            pass
    
    def _save_none_seq_file(self, data, seq_name : str):
        try:
            #만약 시퀀스 명이 fullpath이면 \ 를 제거
            if '\\' in seq_name:
                seq_name = seq_name.split('\\')[-1]

            with open(FILE_PATH+seq_name, 'wb') as fw:
                fw.write(data)
        except Exception as e:
            logger.error('none seq file save error : {}'.format(str(e)))
            return False
        return True

    # sequence data merge
    def _merge_seq_files(self, seq_name : str):
        seq_file_list = [f for f in os.listdir(TMP_FILE_PATH) if f.startswith(seq_name)]
        seq_file_list.sort(key=lambda name : int(name.split('.')[-1]))

        next_seq_num = 1

        # 한 seq씩 저장하도록 변경
        try:
            with open(FILE_PATH+seq_name, 'wb') as merge_f:
                for file in seq_file_list:
                    file_seq_num = file.split('.')[-1]
                    
                    if str(next_seq_num) != file_seq_num and file_seq_num != '4294967295':
                        raise SEQNumError('SEQNumError : seq num is not sequentially [expect={0} / seq={1}]'.format(next_seq_num, file_seq_num))

                    with open(TMP_FILE_PATH+file, 'rb') as seq_f:
                        merge_f.write(seq_f.read())

                    next_seq_num += 1

            self._delete_tmp_files(seq_name)
        except Exception as e:
            raise SEQSaveError('seq save error : {}\npath : {}\nname:{}'.format(str(e), FILE_PATH, seq_name))

    def _split_sending_file(self, file_path, target_ip):
        # TODO 시간되면 f.seek 형식으로 변경 (대용량 파일 전송시 스택에 너무 많은 데이터가 들어감)
        with open(file_path, 'rb') as f:
            data = f.read()

        if '\\' in file_path:
            file_path = file_path.split('\\')[-1]
        if '/' in file_path:
            file_path = file_path.split('/')[-1]
        if '.' in file_path:
            file_path = file_path.split('.')[0]

        data_len = len(data)

        send_count = int(data_len//SEQ_SIZE)
        send_count += 1 if (data_len % SEQ_SIZE) > 0 else 0

        if send_count == 0 or send_count == 1:
            self._save_seq_file(target_ip + '_' + file_path, 0, data)
            return

        for i in range(1, send_count):
            self._save_seq_file(target_ip + '_' + file_path, i, data[SEQ_SIZE*(i-1):SEQ_SIZE*i])
        
        self._save_seq_file(target_ip + '_' + file_path, 0xffffffff, data[SEQ_SIZE*(send_count-1):])

        del data # 빠른 데이터 제거

        return

    def _get_sending_seq_data(self, file_name):
        seq_file_list = [f for f in os.listdir(TMP_FILE_PATH) if f.startswith(file_name)]
        
        if len(seq_file_list) < 1:
            raise SEQLoadError('no file exist')

        seq_file_list.sort(key=lambda name : int(name.split('.')[-1]))

        try:
            with open(TMP_FILE_PATH+seq_file_list[0], 'rb') as f:
                data = f.read()
                
            os.remove(TMP_FILE_PATH+seq_file_list[0])
            
            return [seq_file_list[0].split('.')[-1], data]
        except Exception as e:
            raise SEQLoadError('no file exist')

    # remove tmp file
    def _delete_tmp_files(self, seq_name : str):
        seq_file_list = [f for f in os.listdir(TMP_FILE_PATH) if f.startswith(seq_name)]
        
        for tmp_file in seq_file_list:
            os.remove(TMP_FILE_PATH+tmp_file)

class EncodingMixin():

    # 1st encoding이 안됐을 경우 실행할 함수
    def sub_decoding():
        pass



"""
    Custom Exceptions
"""

class SEQNumError(Exception):
    pass

class SEQSaveError(Exception):
    pass

class SEQLoadError(Exception):
    pass