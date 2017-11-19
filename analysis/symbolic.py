from collections import namedtuple

AddOp = namedtuple('AddOp', ('var_0', 'var_1'))


class SymbolicEmu:
    '''
    Symbolic emulator, used for CFG extraction to see if the next instruction has a known address. A faster but less
    complete version of block simplification.

    To simulate the stack reasonably we assume that esp is separate from every other memory access.
    '''

    # XXX make this generic enough to be usable in test_extract.py and in sa_mem_elim

    def __init__(self):
        # the affected regs form a tree so we can just store the parent
        self.affect_regs = {
            'al': 'ax', 'ah': 'ax', 'ax': 'eax',
            'cl': 'cx', 'ch': 'cx', 'cx': 'ecx',
            'dl': 'dx', 'dh': 'dx', 'dx': 'edx',
            'bl': 'bx', 'bh': 'bx', 'bx': 'ebx',
            'sp': 'esp',
            'bp': 'ebp',
            'si': 'esi',
            'di': 'edi',
        }
        self.regs = {
            'al': None, 'ah': None, 'ax': None, 'eax': 'eax_0',
            'cl': None, 'ch': None, 'cx': None, 'ecx': 'ecx_0',
            'dl': None, 'dh': None, 'dx': None, 'edx': 'edx_0',
            'bl': None, 'bh': None, 'bx': None, 'ebx': 'ebx_0',
            'sp': None, 'esp': 'esp_0',
            'bp': None, 'ebp': 'ebp_0',
            'si': None, 'esi': 'esi_0',
            'di': None, 'edi': 'edi_0',
            'eip': None,
            'cf': False, 'pf': True, 'af': False, 'zf': True, 'sf': False, 'tf': False, 'df': False, 'of': False,
        }

    def propagate_affected(self, reg):
        while reg in self.affect_regs:
            self.regs[reg] = None
            reg = self.affect_regs[reg]

    def emu(self, instrs):
        instr_stack = []
        condition = True
        for instr in instrs.split(','):
            if condition is False:
                continue
            elif condition is None:
                raise ValueError('unknown condition')
            if str.isdecimal(instr):
                instr_stack.append(int(instr))
            elif instr.startswith('0x'):
                instr_stack.append(int(instr, 16))
            elif instr in self.regs:
                instr_stack.append(instr)
            elif instr.startswith('$'):
                instr_stack.append(self.regs[instr])
            elif instr == '=':
                reg, val = instr_stack.pop(), instr_stack.pop()
                self.regs[reg] = self.regs[val]
                self.propagate_affected(reg)
            elif instr == '+=':
                # XXX process flags
                reg, val = instr_stack.pop(), instr_stack.pop()
                self.regs[reg] += self.regs[val]
                self.propagate_affected(reg)
            elif instr == '^=':
                # XXX process flags
                reg, val = instr_stack.pop(), instr_stack.pop()
                self.regs[reg] ^= self.regs[val]
                self.regs['zf'] = self.regs[reg] = 0
                self.propagate_affected(reg)
            elif instr == '=[4]':
                addr, val = instr_stack.pop(), instr_stack.pop()
                self.mem[addr] = self.regs[val]
            elif instr == '[4]':
                instr_stack.append(self.mem[instr_stack.pop()])
            elif instr == '?{':
                condition = instr_stack.pop()
            elif instr == '}':
                condition = True
            else:
                raise ValueError('instr', instr)

        pass

    def emu_api_call(self, stack_size):
        pass
