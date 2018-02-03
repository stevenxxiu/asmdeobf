from collections import defaultdict
from copy import deepcopy

from analysis.block import Block, block_simplify
from analysis.utils import MemValues, is_var

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

    def __init__(self, vars_=None, stack_values=None):
        self.vars = vars_ or {}
        self.mem_var = 0
        self.mem = MemValues()
        self.stack = MemValues(stack_values)

    def __eq__(self, other):
        return (
            self.vars == other.vars and self.stack.values == other.stack.values and
            self.mem_var == other.mem_var and self.mem.values == other.mem.values
        )

    @staticmethod
    def from_func_init():
        self = ConstConstraint()
        self.vars = {name: (f'{name}_0', 0) for name, bits in self.bits.items() if bits == 32}
        return self

    @classmethod
    def from_oep(cls):
        self = cls.from_func_init()
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
            if val_1 == val_2 or instr[3] == instr[4]:
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
            if val_1 == val_2 or instr[3] == instr[4]:
                val = 0
            elif isinstance(val_1, int) and isinstance(val_2, int):
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

    def step_ret(self, stack_change):
        # vars at the end of api call don't have underscore
        for var in list(self.vars):
            if var != 'esp':
                self.vars.pop(var)
        self.mem.invalidate()
        val = self.vars.get('esp', None)
        if isinstance(val, tuple) and val[0] == 'esp_0':
            if (-stack_change, 4) in self.stack.values:
                self.vars['eip'] = self.stack.values[(-stack_change, 4)]
            for mem_offset, mem_size in list(self.stack.values):
                if mem_offset < val[1] + stack_change:
                    self.stack.values.pop((mem_offset, mem_size))
            self.vars['esp'] = (val[0], val[1] + stack_change)
        else:
            self.stack.invalidate()

    def finalize(self):
        for name in list(self.vars):
            if name not in self.bits:
                self.vars.pop(name)


class DisjunctConstConstraint:
    '''
    A disjunction of const constraints, to constrain jcc's. Only the flags are allowed to vary on finalize, to keep
    the # of constraints reasonable (other vars are allowed to change on step so we can compute tmp vars).
    '''
    flags = ['cf', 'pf', 'af', 'zf', 'sf', 'tf', 'df', 'of']

    def __init__(self, const_cons=None):
        self.const_cons = const_cons or []
        self.flag_instrs = []

    def __eq__(self, other):
        return self.const_cons == other.const_cons

    @staticmethod
    def from_func_init():
        return DisjunctConstConstraint([ConstConstraint.from_func_init()])

    @staticmethod
    def from_oep():
        return DisjunctConstConstraint([ConstConstraint.from_oep()])

    @staticmethod
    def _expand_constraints(tuple_cons):
        # go through each flag
        if not tuple_cons:
            return []
        for i in range(len(tuple_cons[0])):
            res = []
            for con in tuple_cons:
                if con[i] is None:
                    res.append(con[:i] + (0,) + con[i + 1:])
                    res.append(con[:i] + (1,) + con[i + 1:])
                else:
                    res.append(con)
            tuple_cons = res
        return tuple_cons

    @staticmethod
    def _reduce_constraints(tuple_cons):
        # go through each flag
        if not tuple_cons:
            return []
        for i in range(len(tuple_cons[0])):
            rest_dups = defaultdict(set)
            for con in tuple_cons:
                rest_dups[con[:i] + con[i + 1:]].add(con[i])
            tuple_cons = []
            for rest_val, flag_vals in rest_dups.items():
                tuple_cons.append(rest_val[:i] + (flag_vals.pop() if len(flag_vals) == 1 else None,) + rest_val[i:])
        return tuple_cons

    def widen(self, other):
        self.const_cons.extend(other.const_cons)

    def step(self, instr):
        if instr[0] not in self.flags:
            self.flag_instrs.append(instr)
        for con in self.const_cons:
            con.step(instr)

    def step_ret(self, stack_change):
        for con in self.const_cons:
            con.step_ret(stack_change)

    def solve(self, var, value):
        '''
        Find the constraint at the end so that var == value.

        The solver here brute-forces all flag values, and assumes that they are not modified after being used to
        evaluate the condition.
        '''
        block = Block(instrs=self.flag_instrs)
        block.condition = var
        block_simplify(block, (block.condition,))  # simplify to improve speed
        self.flag_instrs.clear()
        res_cons = []
        for const_con in self.const_cons:
            res_tuple_cons = []
            tuple_cons = self._expand_constraints([tuple(const_con.vars.get(flag, None) for flag in self.flags)])
            for tuple_con in tuple_cons:
                solve_con = ConstConstraint(dict(zip(self.flags, tuple_con)))
                for instr in block.instrs:
                    solve_con.step(instr)
                if block.condition not in solve_con.vars:
                    raise ValueError(f'could not evaluate {block.condition} to a const')
                if solve_con.vars[block.condition] == value:
                    res_tuple_cons.append(tuple_con)
            for tuple_con in self._reduce_constraints(res_tuple_cons):
                res_con = deepcopy(const_con)
                res_con.vars.update({flag: val for flag, val in zip(self.flags, tuple_con) if val is not None})
                res_cons.append(res_con)
        self.const_cons = res_cons

    def finalize(self):
        if not self.const_cons:
            return
        tuple_cons = []
        for const_con in self.const_cons:
            tuple_cons.append(tuple(const_con.vars.pop(flag, None) for flag in self.flags))
        const_widen = self.const_cons[0]
        for const_con in self.const_cons[1:]:
            const_widen.widen(const_con)
        const_widen.finalize()
        self.const_cons = []
        for tuple_con in self._reduce_constraints(self._expand_constraints(tuple_cons)):
            res_con = deepcopy(const_widen)
            res_con.vars.update({flag: val for flag, val in zip(self.flags, tuple_con) if val is not None})
            self.const_cons.append(res_con)
