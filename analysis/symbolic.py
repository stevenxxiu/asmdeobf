from collections import defaultdict
from copy import deepcopy

from sympy import Symbol, sympify

from analysis.winapi import win_api

__all__ = ['ConstConstraint', 'SymbolNames', 'MemValues', 'SymbolicEmu']


class ConstConstraint:
    '''
    Constraints variables to be constant or `esp_0 + const`. Converts to/from a symbolic state.
    oep is assumed if `state is None`.
    '''

    def __init__(self, state=None):
        self.regs = {}
        self.stack = {}
        self.mem = {}
        if state:
            for this, other in (self.regs, state.regs), (self.stack, state.stack.values), (self.mem, state.mem.values):
                for name, val in other.items():
                    this[name] = val if self._is_constant(val) else None
        else:
            for name in SymbolicEmu.bits:
                self.regs[name] = None
            for name, val in {'$c7': 0, '$c15': 0, '$c31': 0, '$p': 1, '$z': 1, '$s': 0, '$o': 0}.items():
                self.regs[name] = sympify(val)

    def __eq__(self, other):
        return self.regs == other.regs and self.stack == other.stack and self.mem == other.mem

    @staticmethod
    def _is_constant(val):
        if val.is_Integer:
            return True
        elif val == Symbol('esp_0'):
            return True
        elif val.is_Add and val.args[0].is_Integer and val.args[1] == Symbol('esp_0'):
            return True
        return False

    def widen(self, other):
        for this, other in (self.regs, other.regs), (self.stack, other.stack), (self.mem, other.mem):
            for name, val in other.items():
                if val is None:
                    this[name] = None

    def to_state(self, names):
        state = SymbolicEmu(names)
        for this, other in (self.regs, state.regs), (self.stack, state.stack.values), (self.mem, state.mem.values):
            for name, val in this.items():
                if val is not None:
                    other[name] = val
        return state


class SymbolNames:
    def __init__(self):
        self.counts = defaultdict(int)

    def __getitem__(self, item):
        res = Symbol(f'{item}_{self.counts[item]}')
        self.counts[item] += 1
        return res


class MemValues:
    def __init__(self, names):
        self.names = names
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

    bits = {
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
        '$c7': 1, '$c15': 1, '$c31': 1, '$p': 1, '$z': 1, '$s': 1, '$o': 1,
    }

    def __init__(self, names):
        self.names = names
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
        self.regs = {reg: self.names[reg] for reg in self.bits}
        self.mem_var = 0
        self.mem = MemValues(self.names)
        self.stack = MemValues(self.names)

    def _propagate_affected(self, reg):
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

    @staticmethod
    def _conv_mem_access(addr):
        '''
        Convert an expression to `var + offset` if possible.
        '''
        if addr.is_Integer:
            return 0, int(addr)
        elif addr.is_Symbol:
            return addr, 0
        elif addr.is_Add and addr.args[0].is_Integer and addr.args[1].is_Symbol:
            return addr.args[1], addr.args[0]
        return None, None

    def _update_flags(self, value, flags):
        for flag in flags:
            if flag == '$c7':
                self.regs[flag] = self.names['cf']
            elif flag == '$c15':
                self.regs[flag] = self.names['cf']
            elif flag == '$c31':
                self.regs[flag] = self.names['cf']
            elif flag == '$p':
                self.regs[flag] = self.names['pf']
            elif flag == '$z':
                self.regs[flag] = sympify(0) if value == 0 else self.names['zf']
            elif flag == '$s':
                self.regs[flag] = self.names['sf']
            elif flag == '$o':
                self.regs[flag] = self.names['of']

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
                self._propagate_affected(reg)
            elif instr == '+=':
                reg, val = instr_stack.pop(), self._conv_instr_val(instr_stack.pop())
                self.regs[reg] = self.regs[reg] + val
                self._update_flags(self.regs[reg], ['$c7', '$c15', '$c31', '$p', '$z', '$s', '$o'])
                self._propagate_affected(reg)
            elif instr == '++=':
                reg = instr_stack.pop()
                self.regs[reg] = self.regs[reg] + 1
                self._update_flags(self.regs[reg], ['$c7', '$c15', '$c31', '$p', '$z', '$s', '$o'])
                self._propagate_affected(reg)
            elif instr == '-=':
                reg, val = instr_stack.pop(), self._conv_instr_val(instr_stack.pop())
                self.regs[reg] = self.regs[reg] - val
                self._update_flags(self.regs[reg], ['$c7', '$c15', '$c31', '$p', '$z', '$s', '$o'])
                self._propagate_affected(reg)
            elif instr == '--=':
                reg, val = instr_stack.pop()
                self.regs[reg] = self.regs[reg] - 1
                self._update_flags(self.regs[reg], ['$c7', '$c15', '$c31', '$p', '$z', '$s', '$o'])
            elif instr == '^=':
                reg, val = instr_stack.pop(), self._conv_instr_val(instr_stack.pop())
                self.regs[reg] = sympify(0) if self.regs[reg] == val else self.names[reg]
                self._update_flags(self.regs[reg], ['$p', '$z', '$s'])
                self._propagate_affected(reg)
            elif instr.startswith('=['):
                addr, val = self._conv_instr_val(instr_stack.pop()), self._conv_instr_val(instr_stack.pop())
                size = int(instr[2:-1])
                var, offset = self._conv_mem_access(addr)
                if var not in (self.mem_var, Symbol('esp_0')):
                    self.mem_var = var
                    self.mem.invalidate()
                if var == Symbol('esp_0'):
                    self.stack.write(offset, size, val)
                elif var is not None:
                    self.mem.write(offset, size, val)
            elif instr.startswith('['):
                addr = self._conv_instr_val(instr_stack.pop())
                size = int(instr[1:-1])
                var, offset = self._conv_mem_access(addr)
                if var == Symbol('esp_0'):
                    val = self.stack.read(offset, size)
                elif var is not None:
                    val = self.mem.read(offset, size)
                else:
                    val = self.names['mem']
                instr_stack.append(val)
            elif instr == '?{':
                condition = self._conv_instr_val(instr_stack.pop())
            elif instr == '}':
                condition = 1
            else:
                raise ValueError('instr', instr)

    def step_api_jmp(self, lib_name, api_name):
        for reg in self.regs:
            if reg != 'esp':
                self.regs[reg] = self.names[reg]
        self.mem.invalidate()
        stack_change = win_api.get_stack_change(lib_name, api_name) + 4
        var, offset = self._conv_mem_access(self.regs['esp'])
        if var == Symbol('esp_0'):
            for mem_offset, mem_size in list(self.stack.values):
                if mem_offset < offset + stack_change:
                    self.stack.values.pop((mem_offset, mem_size))
        else:
            self.stack.invalidate()
        self.regs['esp'] += stack_change
