from collections import defaultdict

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

    # XXX make this generic enough to be usable in test_extract.py

    def __init__(self):
        self.affected = {
            'al': {'ax'}, 'ah': {'ax'}, 'ax': {'eax'},
            'cl': {'cx'}, 'ch': {'cx'}, 'cx': {'ecx'},
            'dl': {'dx'}, 'dh': {'dx'}, 'dx': {'edx'},
            'bl': {'bx'}, 'bh': {'bx'}, 'bx': {'ebx'},
            'sp': {'esp'},
            'bp': {'ebp'},
            'si': {'esi'},
            'di': {'edi'},
        }
        for reg, parents in self.affected.items():
            parent = next(iter(parents))
            while parent in self.affected:
                parent = next(iter(self.affected[parent]))
                parents.add(parent)
        for reg, parents in dict(self.affected).items():
            for parent in parents:
                if parent not in self.affected:
                    self.affected[parent] = set()
                self.affected[parent].add(reg)
        self.names = SymbolNames()
        self.regs = {reg: self.names[reg] for reg in (
            'al', 'ah', 'ax', 'eax',
            'cl', 'ch', 'cx', 'ecx',
            'dl', 'dh', 'dx', 'edx',
            'bl', 'bh', 'bx', 'ebx',
            'sp', 'esp',
            'bp', 'ebp',
            'si', 'esi',
            'di', 'edi',
            'eip',
            'cf', 'pf', 'af', 'zf', 'sf', 'tf', 'df', 'of',
            '$c7', '$c15', '$c31', '$p', '$z', '$s', '$o',
        )}
        self.stack = MemValues(self.names)

    def propagate_affected(self, reg):
        for reg in self.affected.get(reg, []):
            self.regs[reg] = self.names[reg]

    def _conv_val(self, val):
        return self.regs[val] if val in self.regs else sympify(val)

    def step(self, instrs):
        instr_stack = []
        condition = True
        for instr in instrs.split(','):
            if condition is False:
                continue
            elif condition is not True:
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
                reg, val = instr_stack.pop(), self._conv_val(instr_stack.pop())
                self.regs[reg] = val
                self.propagate_affected(reg)
            elif instr == '+=':
                reg, val = instr_stack.pop(), self._conv_val(instr_stack.pop())
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
                reg, val = instr_stack.pop(), self._conv_val(instr_stack.pop())
                self.regs[reg] = 0 if self.regs[reg] == val else self.names[reg]
                self.regs['$p'] = self.names['pf']
                self.regs['$z'] = 0 if self.regs[reg] == 0 else self.names['zf']
                self.regs['$s'] = self.names['sf']
                self.propagate_affected(reg)
            elif instr.startswith('=['):
                addr, val = self._conv_val(instr_stack.pop()), self._conv_val(instr_stack.pop())
                size = int(instr[2:-1])
                if addr == Symbol('esp_0'):
                    self.stack.write(0, size, val)
                elif addr.is_Add and addr.args[1] == Symbol('esp_0') and addr.args[0].is_Integer:
                    self.stack.write(int(addr.args[0]), size, val)
            elif instr.startswith('['):
                addr = self._conv_val(instr_stack.pop())
                size = int(instr[1:-1])
                if addr == Symbol('esp_0'):
                    val = self.stack.read(0, size)
                elif addr.is_Add and addr.args[1] == Symbol('esp_0') and addr.args[0].is_Integer:
                    val = self.stack.read(int(addr.args[0]), size)
                else:
                    val = self.names['mem']
                instr_stack.append(val)
            elif instr == '?{':
                condition = self._conv_val(instr_stack.pop())
            elif instr == '}':
                condition = True
            else:
                raise ValueError('instr', instr)

    def step_api_call(self, stack_size):
        pass


symb_emu = SymbolicEmu()
