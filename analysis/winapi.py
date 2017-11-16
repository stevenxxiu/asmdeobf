import os
import re


class WinAPI:
    def __init__(self, path='../defs'):
        self.stack_changes = {}
        for name in os.listdir(path):
            with open(os.path.join(path, name)) as sr:
                lib_name = None
                cur_stack_changes = {}
                lines = iter(map(str.strip, sr))
                for line in lines:
                    matches = re.match(r'LIBRARY (.+)', line)
                    if matches:
                        lib_name = self.normalize_lib_name(matches.group(1))
                    if line == 'EXPORTS':
                        break
                for line in lines:
                    api_name, change = line.split('@')
                    cur_stack_changes[api_name] = int(change)
                self.stack_changes[lib_name] = cur_stack_changes

    @staticmethod
    def normalize_lib_name(lib_name):
        lib_name = lib_name.lower()
        lib_name = lib_name.replace('"', '')
        lib_name = re.sub(r'\.dll$', '', lib_name)
        return lib_name

    def get_stack_change(self, lib_name, api_name):
        return self.stack_changes[self.normalize_lib_name(lib_name)][api_name]
