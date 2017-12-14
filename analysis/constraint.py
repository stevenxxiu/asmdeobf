from analysis.utils import MemValues, is_var
from analysis.winapi import win_api

__all__ = ['ConstConstraint', 'DisjunctConstConstraint']


class ConstConstraint:
    '''
    Used for CFG extraction to find fake jumps and if the return address is known.

    Constraints variables to be constant or `esp_0 + const`.

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
    }
    assign_bits = {'l': (0, 7), 'h': (8, 15), 'x': (0, 15)}

    def __init__(self):
        self.vars = {}
        self.mem_var = 0
        self.mem = MemValues()
        self.stack = MemValues()

    def __eq__(self, other):
        return (
            self.vars == other.vars and self.stack.values == other.stack.values and
            self.mem_var == other.mem_var and self.mem.values == other.mem.values
        )

    @staticmethod
    def from_oep():
        self = ConstConstraint()
        self.vars = {name: (f'{name}_0', 0) for name, bits in self.bits.items() if bits == 32}
        for name, val in {'cf': 0, 'pf': 1, 'af': 0, 'zf': 1, 'sf': 0, 'tf': 0, 'df': 0, 'of': 0}.items():
            self.vars[name] = val
        return self

    def widen(self, other):
        if self.mem_var != other.mem_var:
            self.mem_var = 0
            self.mem.invalidate()
        for dest, src in [
            (self.vars, other.vars), (self.stack.values, other.stack.values), (self.mem.values, other.mem.values)
        ]:
            for name, val in list(dest.items()):
                if name not in src or src[name] != val:
                    dest.pop(name)

    def _read_var(self, val):
        if isinstance(val, int):
            return val
        elif val in self.vars:
            return self.vars[val]
        else:
            return None

    def _write_var(self, var, val):
        if val is None:
            self.vars.pop(var, None)
        else:
            self.vars[var] = val

    def step(self, instr):
        # compute expression
        val = None
        if isinstance(instr[2], int):
            val = instr[2]
        elif is_var(instr[2]):
            val = self._read_var(instr[2])
        elif instr[2].startswith('$b'):
            val_1 = self._read_var(instr[3])
            if isinstance(val_1, int):
                bit = int(instr[2][2:])
                val = int(bool(int(val_1) & (1 << bit)))
        elif instr[2].startswith('$c'):
            val_1 = self._read_var(instr[3])
            if isinstance(val_1, int):
                bit = int(instr[2][2:]) + 1
                val = int(bool(int(val_1) & (1 << bit)))
        elif instr[2] == '$p':
            pass
        elif instr[2] == '$z':
            val_1 = self._read_var(instr[3])
            if isinstance(val_1, int):
                val = int(val_1 == 0)
            elif isinstance(val_1, tuple) and val_1[0] == 'esp_0':
                val = 0
        elif instr[2] == '$s':
            pass
        elif instr[2] == '$o':
            pass
        elif instr[2] == '!':
            val_1 = self._read_var(instr[3])
            if isinstance(val_1, int):
                val = 1 - val_1
        elif instr[2] == '&':
            val_1, val_2 = self._read_var(instr[3]), self._read_var(instr[4])
            if isinstance(val_1, int) and isinstance(val_2, int):
                val = val_1 & val_2
        elif instr[2] == '|':
            val_1, val_2 = self._read_var(instr[3]), self._read_var(instr[4])
            if isinstance(val_1, int) and isinstance(val_2, int):
                val = val_1 | val_2
        elif instr[2] == '^':
            val_1, val_2 = self._read_var(instr[3]), self._read_var(instr[4])
            if instr[3] == instr[4]:
                val = 0
            elif isinstance(val_1, int) and isinstance(val_2, int):
                val = val_1 ^ val_2
        elif instr[2] == '+':
            val_1, val_2 = self._read_var(instr[3]), self._read_var(instr[4])
            if isinstance(val_1, int) and isinstance(val_2, int):
                val = val_1 + val_2
            elif isinstance(val_1, int) and isinstance(val_2, tuple):
                val = (val_2[0], val_2[1] + val_1)
            elif isinstance(val_1, tuple) and isinstance(val_2, int):
                val = (val_1[0], val_1[1] + val_2)
        elif instr[2] in ('==', '-'):
            val_1, val_2 = self._read_var(instr[3]), self._read_var(instr[4])
            if isinstance(val_1, int) and isinstance(val_2, int):
                val = val_1 - val_2
            elif isinstance(val_1, tuple) and isinstance(val_2, int):
                val = (val_1[0], val_1[1] - val_2)
        elif instr[2] == '*':
            val_1, val_2 = self._read_var(instr[3]), self._read_var(instr[4])
            if isinstance(val_1, int) and isinstance(val_2, int):
                val = val_1 * val_2
        else:
            raise ValueError('instr', instr)

        # assign
        if instr[1] == '=':
            var_name = instr[0].split('_')[0]
            if isinstance(val, int) and var_name in self.bits:
                val = val & ((1 << self.bits[var_name]) - 1)
            self._write_var(instr[0], val)
        elif instr[1] in ('l=', 'h=', 'x='):
            parent_val = self.vars.get(instr[0], None)
            if isinstance(val, int) and isinstance(parent_val, int):
                bits = self.assign_bits[instr[1][0]]
                mask = ((1 << (bits[1] - bits[0] + 1)) - 1) << bits[0]
                val = (parent_val & ~mask) | (int(val) << bits[0])
            else:
                val = None
            self._write_var(instr[0], val)
        elif instr[1] in ('=l', '=h', '=x'):
            if isinstance(val, int):
                bits = self.assign_bits[instr[1][1]]
                mask = ((1 << (bits[1] - bits[0] + 1)) - 1) << bits[0]
                val = (int(val) & mask) >> bits[0]
            else:
                val = None
            self._write_var(instr[0], val)
        elif instr[1].startswith('=['):
            val, addr = None, val
            if isinstance(addr, int):
                addr = (0, addr)
            if isinstance(addr, tuple):
                size = int(instr[1][2:-1])
                if addr[0] == 'esp_0':
                    val = self.stack.read(addr[1], size)
                elif addr[0] == self.mem_var:
                    val = self.mem.read(addr[1], size)
            self._write_var(instr[0], val)
        elif instr[1].endswith(']='):
            if val is not None:
                size = int(instr[1][1:-2])
                addr = self._read_var(instr[0])
                if isinstance(addr, int):
                    addr = (0, addr)
                if isinstance(addr, tuple):
                    if addr[0] not in (self.mem_var, 'esp_0'):
                        self.mem_var = addr[0]
                        self.mem.invalidate()
                    if addr[0] == 'esp_0':
                        self.stack.write(addr[1], size, val)
                    elif addr[0] == self.mem_var:
                        self.mem.write(addr[1], size, val)
        else:
            raise ValueError('instr', instr)

    def step_api_jmp(self, lib_name, api_name):
        # vars at the end of api call don't have underscore
        for var in list(self.vars):
            if var != 'esp':
                self.vars.pop(var)
        self.mem.invalidate()
        stack_change = win_api.get_stack_change(lib_name, api_name) + 4
        val = self.vars.get('esp', None)
        if isinstance(val, tuple) and val[0] == 'esp_0':
            for mem_offset, mem_size in list(self.stack.values):
                if mem_offset < val[1] + stack_change:
                    self.stack.values.pop((mem_offset, mem_size))
            self.vars['esp'] = (val[0], val[1] + stack_change)
        else:
            self.stack.invalidate()


class DisjunctConstConstraint:
    '''
    Allows flag values to be a disjunction when widening.
    '''

    @staticmethod
    def from_predicate(instrs, predicate):
        pass
