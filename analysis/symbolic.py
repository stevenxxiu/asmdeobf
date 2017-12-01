from collections import defaultdict
from copy import deepcopy

from sympy import Symbol, sympify

__all__ = ['ConstConstraint', 'MemValues', 'SymbolicEmu']


class ConstConstraint:
    def __init__(self, state):
        # XXX get constraints
        pass

    def widen(self, other):
        pass

    def to_state(self):
        pass


class SymbolNames:
    def __init__(self):
        self.counts = defaultdict(int)

    def __getitem__(self, item):
        res = Symbol(f'{item}_{self.counts[item]}')
        self.counts[item] += 1
        return res


class MemValues:
    def __init__(self, names=None):
        self.names = names or {'mem': None}
        self.values = {}  # {(offset, size): value}

    def write(self, offset, size, value, can_overlap=True):
        if can_overlap:
            for cache_offset, cache_size in list(self.values):
                if offset < cache_offset + cache_size and cache_offset < offset + size:
                    self.values.pop((cache_offset, cache_size))
        self.values[(offset, size)] = value

    def has(self, offset, size):
        return (offset, size) in self.values

    def read(self, offset, size):
        return self.values.get((offset, size), self.names['mem'])

    def invalidate(self):
        self.values.clear()


class SymbolicEmu:
    '''
    Symbolic emulator, used for CFG extraction to see if the next instruction has a known address. A faster but less
    complete version of block simplification.

    We assume the stack is separate from every other memory access, which is still sound enough.
    '''

    def __init__(self):
        self.bits = {
            'al': 8, 'ah': 8, 'ax': 16, 'eax': 32,
            'cl': 8, 'ch': 8, 'cx': 16, 'ecx': 32,
            'dl': 8, 'dh': 8, 'dx': 16, 'edx': 32,
            'bl': 8, 'bh': 8, 'bx': 16, 'ebx': 32,
            'sp': 16, 'esp': 32,
            'bp': 16, 'ebp': 32,
            'si': 16, 'esi': 32,
            'di': 16, 'edi': 32,
            'eip': 32,
            'cf': 1, 'pf': 1, 'af': 1, 'zf': 1, 'sf': 1, 'tf': 1, 'df': 1, 'of': 1,
        }
        self.affected = {
            'al': {'ax': (0, 7)}, 'ah': {'ax': (8, 15)}, 'ax': {'eax': (0, 15)},
            'cl': {'cx': (0, 7)}, 'ch': {'cx': (8, 15)}, 'cx': {'ecx': (0, 15)},
            'dl': {'dx': (0, 7)}, 'dh': {'dx': (8, 15)}, 'dx': {'edx': (0, 15)},
            'bl': {'bx': (0, 7)}, 'bh': {'bx': (8, 15)}, 'bx': {'ebx': (0, 15)},
            'sp': {'esp': (0, 15)},
            'bp': {'ebp': (0, 15)},
            'si': {'esi': (0, 15)},
            'di': {'edi': (0, 15)},
        }
        for reg, parents in self.affected.items():
            ancestor, bits = next(iter(parents.items()))
            cur_start = bits[0]
            while ancestor in self.affected:
                ancestor, bits = next(iter(self.affected[ancestor].items()))
                cur_start += bits[0]
                parents[ancestor] = (cur_start, cur_start + self.bits[reg] - 1)
        for reg, parents in deepcopy(self.affected).items():
            for parent in parents:
                if parent not in self.affected:
                    self.affected[parent] = {}
                self.affected[parent][reg] = (0, self.bits[reg] - 1)
        self.names = SymbolNames()
        self.regs = {reg: self.names[reg] for reg in self.bits}
        self.regs.update({name: sympify(val) for name, val in {
            '$c7': 0, '$c15': 0, '$c31': 0, '$p': 1, '$z': 1, '$s': 0, '$o': 0,
        }.items()})
        self.stack = MemValues(self.names)

    def propagate_affected(self, reg):
        for parent, bits in self.affected.get(reg, {}).items():
            if self.regs[parent].is_Integer and self.regs[reg].is_Integer:
                parent_val = int(self.regs[parent])
                reg_val = int(self.regs[reg])
                mask = ((1 << (bits[1] - bits[0] + 1)) - 1) << bits[0]
                self.regs[parent] = sympify((parent_val & ~mask) | (reg_val << bits[0]))
            else:
                self.regs[parent] = self.names[parent]

    def _conv_instr_val(self, val):
        return self.regs[val] if val in self.regs else sympify(val)

    def step(self, instrs):
        instr_stack = []
        condition = 1
        for instr in instrs.split(','):
            if condition == 0:
                continue
            elif condition != 1:
                raise ValueError('unknown condition')
            if str.isdecimal(instr):
                instr_stack.append(int(instr))
            elif instr.startswith('0x'):
                instr_stack.append(int(instr, 16))
            elif instr in self.regs:
                instr_stack.append(instr)
            elif instr == '$0':
                instr_stack.append(0)
            elif instr == '$1':
                instr_stack.append(1)
            elif instr == '=':
                reg, val = instr_stack.pop(), self._conv_instr_val(instr_stack.pop())
                self.regs[reg] = val
                self.propagate_affected(reg)
            elif instr == '+=':
                reg, val = instr_stack.pop(), self._conv_instr_val(instr_stack.pop())
                self.regs[reg] = self.regs[reg] + val
                self.regs['$c7'] = self.names['cf']
                self.regs['$c15'] = self.names['cf']
                self.regs['$c31'] = self.names['cf']
                self.regs['$p'] = self.names['pf']
                self.regs['$z'] = self.names['zf']
                self.regs['$s'] = self.names['sf']
                self.regs['$o'] = self.names['of']
                self.propagate_affected(reg)
            elif instr == '^=':
                reg, val = instr_stack.pop(), self._conv_instr_val(instr_stack.pop())
                self.regs[reg] = sympify(0) if self.regs[reg] == val else self.names[reg]
                self.regs['$p'] = self.names['pf']
                self.regs['$z'] = sympify(0) if self.regs[reg] == 0 else self.names['zf']
                self.regs['$s'] = self.names['sf']
                self.propagate_affected(reg)
            elif instr.startswith('=['):
                addr, val = self._conv_instr_val(instr_stack.pop()), self._conv_instr_val(instr_stack.pop())
                size = int(instr[2:-1])
                if addr == Symbol('esp_0'):
                    self.stack.write(0, size, val)
                elif addr.is_Add and addr.args[1] == Symbol('esp_0') and addr.args[0].is_Integer:
                    self.stack.write(int(addr.args[0]), size, val)
            elif instr.startswith('['):
                addr = self._conv_instr_val(instr_stack.pop())
                size = int(instr[1:-1])
                if addr == Symbol('esp_0'):
                    val = self.stack.read(0, size)
                elif addr.is_Add and addr.args[1] == Symbol('esp_0') and addr.args[0].is_Integer:
                    val = self.stack.read(int(addr.args[0]), size)
                else:
                    val = self.names['mem']
                instr_stack.append(val)
            elif instr == '?{':
                condition = self._conv_instr_val(instr_stack.pop())
            elif instr == '}':
                condition = 1
            else:
                raise ValueError('instr', instr)

    def step_api_call(self, stack_size):
        pass
