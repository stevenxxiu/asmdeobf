import re

from analysis.block import Block
from analysis.func import Function
from analysis.winapi import WinAPI


class FuncExtract:
    def __init__(self, r):
        self.r = r
        self.winapi = WinAPI()

    def extract_esil(self, addr):
        '''
        Get esil at addr. Requires `e asm.esil=true`.
        '''
        # update eip to facilitate analysis of conditional jmps and call
        res = self.r.cmdj(f'pdj 1 @ {addr}')[0]
        return f'{addr + res["size"]},eip,=,{res["esil"]}'

    def extract_func(self, start_addr, funcs, is_oep_func, assume_new, end_addrs):
        assume_new = set(assume_new)
        end_addrs = set(end_addrs)

        addr_to_block = {}  # {addr: (block, i)}
        block_to_addr = {}  # {(block, i): addr}
        stack = [(start_addr, {}, {})]  # [(addr, emu_state, flags)]
        is_oep_block = is_oep_func

        self.r.cmd('aei')
        self.r.cmd('aeim')

        while stack:
            cur_addr, emu_state, flags = stack.pop()
            block = Block()

            # update emulator
            for state in emu_state, flags:
                for var, val in state.items():
                    if var is not None:
                        self.r.cmd(f'aer {var}={val}')
            self.r.cmd(f's {cur_addr}')
            self.r.cmd('aeip')

            while True:
                cur_addr = self.r.cmdj('aerj')['eip']
                if cur_addr == 0:
                    break

                # if address is already found (through conditional jmps)
                if cur_addr in addr_to_block and cur_addr not in assume_new:
                    block.children = [cur_addr]
                    block, i = addr_to_block[cur_addr]
                    if i == 0:
                        break
                    # split block in 2
                    n = len(block.instrs)
                    new_block = Block(block.instrs[:i], [cur_addr])
                    block.instrs = block.instrs[i:]
                    for j in range(i):
                        addr_to_block[block_to_addr[(id(block), j)]] = new_block, j
                    for j in range(i, n):
                        addr_to_block[block_to_addr[(id(block), j)]] = block, j - i
                    for j in range(i):
                        block_to_addr[(id(new_block), j)] = block_to_addr.pop((id(block), j))
                    for j in range(i, n):
                        block_to_addr[(id(block), j - i)] = block_to_addr.pop((id(block), j))
                    break

                instr = self.extract_esil(cur_addr)
                addr_to_block[cur_addr] = (block, len(block.instrs))
                block_to_addr[(id(block), len(block.instrs))] = cur_addr
                block.instrs.append(instr)

                # check if ended by user action
                if cur_addr in end_addrs:
                    break

                # update certain flag values for conditional branches
                for value, flag in re.findall(r'(\$\w+),(\wf),=', instr):
                    flags[flag] = 0 if value == '$0' else 1 if value == '$1' else None
                if re.match(r'\d+,eip,=,(\w+),\1,\^=', instr):
                    flags['zf'] = 0

                # check if we have a conditional jmp
                matches = re.match(r'(\d+),eip,=,(\wf),(!,)?\?{,(\d+),eip,=,}', instr)
                if matches and not is_oep_block:
                    flag = matches.group(2)
                    if flags.get(flag, None) is None:
                        is_negated = bool(matches.group(3))
                        # explore remaining code first before exploring jmp
                        emu_state = self.r.cmdj('aerj')
                        stack.append((int(matches.group(4)), emu_state, {flag: int(not is_negated)}))
                        stack.append((int(matches.group(1)), emu_state, {flag: int(is_negated)}))
                        block.condition = (flag, is_negated)
                        block.children = [int(matches.group(4)), int(matches.group(1))]
                        break

                # check if instruction is a call to api
                matches = re.match(r'(\d+),eip,=,eip,4,esp,-=,esp,=\[\],(\d+),eip,=', instr)
                if matches:
                    ret_addr, call_addr = matches.group(1), matches.group(2)
                    matches = re.match(r'(0x\d+),\[\],eip,=', self.r.cmdj(f'pdj 1 @ {call_addr}')[0]['esil'])
                if matches:
                    api_addr = matches.group(1)
                    matches = re.match(r'sym\.imp\.(\S+)_(\S+)$', self.r.cmd(f'fd {api_addr}'))
                if matches:
                    # end current block to aid in de-obfuscation
                    lib_name, api_name = matches.group(1), matches.group(2)
                    self.r.cmd(f'ae {self.winapi.get_stack_change(lib_name, api_name)},esp,+=')
                    emu_state = self.r.cmdj('aerj')
                    stack.append((int(ret_addr), emu_state, {}))
                    block.children = [int(ret_addr)]
                    break

                # check if instruction is a call to a proc
                # check if function was already analyzed

                self.r.cmd('aes')
            is_oep_block = False

        addrs = {start_addr}
        for block, i in addr_to_block.values():
            addrs.update(block.children)
        funcs[start_addr] = Function(start_addr, {addr: addr_to_block[addr][0] for addr in addrs})

    def extract_funcs(self, addr, is_oep_func=True, assume_new=(), end_addrs=()):
        funcs = {}
        self.extract_func(addr, funcs, is_oep_func, assume_new, end_addrs)
        return sorted(funcs.values())
