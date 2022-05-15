import os
from Exceptions import SEQNumError, SEQSaveError, SEQLoadError

class SEQManager:
    TMP_FILE_PATH = './tmp/'
    f_extension = '.seq.{}'

    # tmp 폴더에 <file name>.seq.<seq num> 형식으로 저장
    @classmethod
    def saveSeqData(cls, seq_name : str, seq_num : int, data : bytes):
        file_name = cls.TMP_FILE_PATH+seq_name+cls.f_extension.format(seq_num)

        if os.path.isfile(file_name):
            raise SEQNumError('SEQNumError : seq num has overlap..!')

        try:
            with open(file_name, 'wb') as f:
                f.write(data)
                pass
        except:
            pass

    @classmethod
    def getSeqData(cls, file_name):
        seq_file_list = [f for f in os.listdir(cls.TMP_FILE_PATH) if f.startswith(file_name)]
        
        if len(seq_file_list) < 1:
            raise SEQLoadError('no file exist')

        seq_file_list.sort(key=lambda name : int(name.split('.')[-1]))

        try:
            with open(cls.TMP_FILE_PATH+seq_file_list[0], 'rb') as f:
                data = f.read()
                
            os.remove(cls.TMP_FILE_PATH+seq_file_list[0])
            
            return [seq_file_list[0].split('.')[-1], data]
        except Exception as e:
            raise SEQLoadError('no file exist')
    
    # tmp 폴더의 시퀀스 데이터 merge 작업
    @classmethod
    def mergeSeqData(cls, seq_name, save_path):
        seq_file_list = [f for f in os.listdir(cls.TMP_FILE_PATH) if f.startswith(seq_name)]
        seq_file_list.sort(key=lambda name : int(name.split('.')[-1]))

        next_seq_num = 1

        try:
            with open(save_path+seq_name, 'wb') as merge_f:
                for file in seq_file_list:
                    file_seq_num = file.split('.')[-1]
                    
                    if str(next_seq_num) != file_seq_num and file_seq_num != '4294967295':
                        raise SEQNumError('SEQNumError : seq num is not sequentially [expect={0} / seq={1}]'.format(next_seq_num, file_seq_num))

                    with open(cls.TMP_FILE_PATH+file, 'rb') as seq_f:
                        merge_f.write(seq_f.read())

                    next_seq_num += 1

            cls.deleteTmpData(seq_name)
        except Exception as e:
            raise SEQSaveError('seq save error : {}\npath : {}\nname:{}'.format(str(e), save_path, seq_name))
        return True

    # 시퀀스 데이터들 제거
    @classmethod
    def deleteTmpData(cls, seq_name):
        seq_file_list = [f for f in os.listdir(cls.TMP_FILE_PATH) if f.startswith(seq_name)]
        
        for tmp_file in seq_file_list:
            os.remove(cls.TMP_FILE_PATH+tmp_file)

    