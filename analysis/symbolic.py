from collections import namedtuple

__all__ = ['merge_state', 'is_sub_state', 'MemValues', 'SymbolicEmu']

AddOp = namedtuple('AddOp', ('expr_1', 'expr_2'))


def simplify_add(expr):
    if isinstance(expr.expr_1, int) and isinstance(expr.expr_2, int):
        expr = expr.expr_1 + expr.expr_2
    elif isinstance(expr.expr_1, AddOp) and isinstance(expr.expr_2, int):
        expr = AddOp(expr.expr_1.expr_1, expr.expr_1.expr_2 + expr.expr_2)
    return expr


def merge_state(state_1, state_2):
    pass


def is_sub_state(state_1, state_2):
    pass


class MemValues:
    def __init__(self):
        self.values = {}  # {(offset, size): value}

    def write(self, offset, size, value, can_overlap=True):
        if can_overlap:
            for cache_offset, cache_size in list(self.values):
                if offset < cache_offset + cache_size and cache_offset < offset + size:
                    self.values.pop((cache_offset, cache_size))
        self.values[(offset, size)] = value

    def read(self, offset, size):
        return self.values.get((offset, size), None)

    def invalidate(self):
        self.values.clear()


class SymbolicEmu:
    '''
    Symbolic emulator, used for CFG extraction to see if the next instruction has a known address. A faster but less
    complete version of block simplification.

    We assume the stack is separate from every other memory access, which is still sound enough.
    '''

    # XXX make this generic enough to be usable in test_extract.py

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
        self.stack = MemValues()

    def propagate_affected(self, reg):
        while reg in self.affect_regs:
            self.regs[reg] = None
            reg = self.affect_regs[reg]

    def _conv_val(self, val):
        return val if isinstance(val, int) else self.regs[val]

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
                self.regs[reg] = self._conv_val(val)
                self.propagate_affected(reg)
            elif instr == '+=':
                reg, val = instr_stack.pop(), instr_stack.pop()
                self.regs[reg] = simplify_add(AddOp(self.regs[reg], self._conv_val(val)))
                self.regs['cf'] = None
                self.regs['pf'] = None
                self.regs['af'] = None
                self.regs['zf'] = None
                self.regs['sf'] = None
                self.regs['of'] = None
                self.propagate_affected(reg)
            elif instr == '^=':
                reg, val = instr_stack.pop(), instr_stack.pop()
                val = self._conv_val(val)
                self.regs[reg] = 0 if self.regs[reg] == val else None
                self.regs['cf'] = 0
                self.regs['pf'] = None
                self.regs['zf'] = 0 if self.regs[reg] == 0 else None
                self.regs['sf'] = None
                self.regs['of'] = 0
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

    def emu_api_call(self, stack_size):
        pass
