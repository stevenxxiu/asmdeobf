import itertools
from collections import defaultdict

from analysis.utils import MemValues, is_var

__all__ = ['Block', 'block_simplify']


class Block:
    '''
    split() & merge() keeps upper-half in the graph, so that data structures which reference self do not need to be
    modified, since this is the more common use case, and the implementation is simpler.
    '''

    def __init__(self, addr_sizes=(), instrs=None):
        '''
        instr is of the form: (dest, assign_op, ...).
        '''
        self.addr_sizes = set(addr_sizes)
        self.instrs = instrs or []
        self.call = None
        self.condition = None
        self.parents = set()  # should not be modified directly by users
        self._children = ()

    def __hash__(self):
        return id(self)

    def __str__(self):
        lines = []
        for instr in self.instrs:
            parts = [f'0x{part:x}' if isinstance(part, int) else part for part in instr]
            arity = len(parts) - 3
            if arity == 0:
                lines.append(f'{parts[0]} {parts[1]} {parts[2]}')
            elif arity == 1:
                lines.append(f'{parts[0]} {parts[1]} {parts[2]} {parts[3]}')
            elif arity == 2:
                lines.append(f'{parts[0]} {parts[1]} {parts[3]} {parts[2]} {parts[4]}')
            else:
                raise ValueError
        if self.call:
            lines.append(f'jmp to {self.call[0]}!{self.call[1]}')
        if self.condition:
            lines.append(f'jmp left if {self.condition}')
        return '\n'.join(lines)

    def split(self, i, addr_i=None):
        lower_half = Block(addr_sizes=self.addr_sizes, instrs=self.instrs[i:])
        lower_half.condition = self.condition
        lower_half.children = self.children
        self.instrs = self.instrs[:i]
        self.children = ()
        if addr_i:
            self.addr_sizes = {(addr, size) for addr, size in self.addr_sizes if addr < addr_i}
            lower_half.addr_sizes = {(addr, size) for addr, size in lower_half.addr_sizes if addr >= addr_i}
        return lower_half

    def merge(self, lower_half):
        self.instrs.extend(lower_half.instrs)
        self.call = lower_half.call
        self.condition = lower_half.condition
        self.children = lower_half.children
        self.addr_sizes.update(lower_half.addr_sizes)
        lower_half.children = ()

    @property
    def children(self):
        return self._children

    @children.setter
    def children(self, value):
        # use tuple to force setting through this setter so parents are always updated
        if not isinstance(value, tuple):
            raise ValueError
        for child in self.children:
            child.parents.remove(self)
        for child in value:
            child.parents.add(self)
        self._children = value
        if len(value) < 2:
            self.condition = None

    def dfs(self):
        '''
        DFS is more natural for unit tests (matches esil order).
        Children can be modified during traversal.
        '''
        visited = set()
        stack = [self]
        while stack:
            block = stack.pop()
            if id(block) not in visited:
                yield block
                visited.add(id(block))
                stack.extend(reversed(block.children))


def sa_to_ssa(instrs):
    '''
    Convert to ssa form.
    '''
    instrs_new = []
    var_map = {}
    var_num = defaultdict(int)
    for instr in instrs:
        instr_new = list(instr)
        for i in list(range(2, len(instr))) + [0]:
            instr_part = instr[i]
            if is_var(instr_part):
                is_assign = i == 0 and not instr[1].endswith(']=')
                if is_assign or instr_part not in var_map:
                    name_part = instr_part.split('_')[0]
                    if is_assign:
                        var_num[name_part] += 1
                    var_map[instr_part] = f'{name_part}_{var_num[name_part]}'
                instr_part = var_map[instr_part]
            instr_new[i] = instr_part
        instrs_new.append(tuple(instr_new))
    return instrs_new, var_map


def ssa_to_sa(instrs):
    '''
    Convert back to sa form.
    '''
    instrs, var_map_ssa = sa_to_ssa(instrs)
    instrs_new = []
    init_vars = {}
    for instr in instrs:
        for part in instr:
            if is_var(part) and part.endswith('_0'):
                init_vars[part.split('_')[0]] = part
    final_vars = {}
    for instr in instrs:
        if not instr[1].endswith(']='):
            if not instr[0].startswith('tmp_'):
                final_vars[instr[0].split('_')[0]] = instr[0]
    var_map_sa = {name: name_part for name_part, name in itertools.chain(init_vars.items(), final_vars.items())}
    for instr in instrs:
        instr = tuple(var_map_sa.get(part, part) for part in instr)
        if not (instr[1] == '=' and instr[0] == instr[2]):
            instrs_new.append(instr)
    return instrs_new, {name: var_map_sa.get(val, val) for name, val in var_map_ssa.items()}


def sa_expr_simp(instrs):
    # simplify expressions involving `r1 ^ r2`
    instrs_new = []
    var_map = {}
    for instr in instrs:
        if instr[2] == '^':
            vars_ = set()
            for var in instr[3:]:
                for var_ in var_map.get(var, [var]):
                    if var_ in vars_:
                        vars_.remove(var_)
                    else:
                        vars_.add(var_)
            vars_ = tuple(sorted(vars_))
            var_map[instr[0]] = vars_
            if len(vars_) == 0:
                instr = instr[:2] + (0,)
            elif len(vars_) == 1:
                instr = instr[:2] + vars_
            elif len(vars_) == 2:
                instr = instr[:2] + ('^',) + vars_
        instrs_new.append(instr)
    instrs = instrs_new

    # simplify expressions involving `r1 - r1`
    instrs_new = []
    for instr in instrs:
        if instr[2] == '-' and instr[3] == instr[4]:
            instr = instr[:2] + (0,)
        instrs_new.append(instr)
    instrs = instrs_new

    # simplify expressions involving `r1 + 1`, `r1 - 1`
    instrs_new = []
    var_map = {}
    for instr in instrs:
        if instr[2] in ('+', '-'):
            var_ = instr[3]
            if var_ in var_map:
                expr_1 = var_map[var_]
                int_1 = -expr_1[2] if expr_1[0] == '-' else expr_1[2]
                expr_2 = instr[2:]
                int_2 = -expr_2[2] if expr_2[0] == '-' else expr_2[2]
                int_res = int_1 + int_2
                if int_res > 0:
                    instr = instr[:2] + ('+', expr_1[1], int_res)
                elif int_res < 0:
                    instr = instr[:2] + ('-', expr_1[1], -int_res)
                else:
                    instr = instr[:2] + (expr_1[1],)
        instrs_new.append(instr)
        if instr[1] == '=' and instr[2] in ('+', '-') and isinstance(instr[4], int):
            var_map[instr[0]] = instr[2:]
    return instrs_new


def sa_common_subexpr(instrs):
    '''
    Common sub-expression elimination.
    '''
    instrs_new = []
    expr_map = {}
    for instr in instrs:
        if instr[2:] in expr_map:
            instr = instr[:2] + (expr_map[instr[2:]],)
        instrs_new.append(instr)
        if instr[1] == '=':
            expr_map[instr[2:]] = instr[0]
    return instrs_new


def sa_sub_assign_retrieve(instrs):
    instrs_new = []
    var_map = {}
    for instr in instrs:
        if len(instr) == 3 and instr[1] in ('l=', 'h=', 'x='):
            var_map[(instr[0], instr[1][0])] = instr[2]
        if len(instr) == 3 and instr[1] in ('=l', '=h', '=x') and (instr[2], instr[1][1]) in var_map:
            instr = instr[:1] + ('=', var_map[(instr[2], instr[1][1])])
        instrs_new.append(instr)
    return instrs_new


def sa_copy_propagate(instrs):
    '''
    This only copies variables and not expressions. Otherwise the following will not be simpler:

        r2 = r1 + 1
        r3 = r2
    '''
    instrs_new = []
    var_map = {}
    for instr in instrs:
        # assignment
        parts = []
        for part in instr[2:]:
            if part in var_map:
                part = var_map[part]
            parts.append(part)
        instr = instr[:2] + tuple(parts)
        # memory write
        if instr[1].endswith(']=') and instr[0] in var_map:
            instr = (var_map[instr[0]],) + instr[1:]
        # store propagated var
        if len(instr) == 3 and instr[1] == '=':
            var_map[instr[0]] = instr[2]
        instrs_new.append(instr)
    return instrs_new


def sa_const_fold(instrs):
    '''
    Constant folding.
    '''
    instrs_new = []
    for instr in instrs:
        if instr[2] == '+' and isinstance(instr[3], int) and isinstance(instr[4], int):
            instr = instr[:2] + (instr[3] + instr[4],)
        elif instr[2] == '-' and isinstance(instr[3], int) and isinstance(instr[4], int):
            instr = instr[:2] + (instr[3] - instr[4],)
        instrs_new.append(instr)
    return instrs_new


def sa_mem_elim(instrs):
    '''
    Track and eliminates useless memory reads and writes. We track the memory of a register with its offsets. We are
    sound and don't assume register bounds.
    '''
    # track memory accesses and replace known memory values
    instrs_new = []
    var_map = {}  # maps `r2` to `(r1, 5)` if we have `r2 = r1 + 5`
    mem_var = 0  # current var memory values are based upon
    mem_values = MemValues()
    mem_instrs = defaultdict(dict)  # {(var_, offset, size): instr_i}, eliminates dead writes
    dead_instrs = set()
    for i, instr in enumerate(instrs):
        if instr[1] == '=' and instr[2] in ('+', '-') and isinstance(instr[4], int):
            var_map[instr[0]] = (instr[3], instr[4] if instr[2] == '+' else -instr[4])
        elif instr[1].endswith(']='):
            var = instr[0]
            var, offset = (0, var) if isinstance(var, int) else var_map.get(var, (var, 0))
            size = int(instr[1][1:-2])
            # check for dead writes
            if (var, offset, size) in mem_instrs:
                dead_instrs.add(mem_instrs[(var, offset, size)])
            mem_instrs[(var, offset, size)] = i
            # store value
            if var != mem_var:
                mem_var = var
                mem_values.invalidate()
            mem_values.write(offset, size, instr[2:])
        elif instr[1].startswith('=[') and len(instr) == 3:
            var = instr[2]
            var, offset = (0, var) if isinstance(var, int) else var_map.get(var, (var, 0))
            size = int(instr[1][2:-1])
            if var == mem_var and mem_values.has(offset, size):
                # we know the value, so don't need to read from memory
                instr = (instr[0], '=') + mem_values.read(offset, size)
            else:
                # we don't know the value, writes which could have written to this are useful
                for write_var, write_offset, write_size in list(mem_instrs):
                    if write_var != var or (offset < write_offset + write_size and write_offset < offset + size):
                        mem_instrs.pop((write_var, write_offset, write_size))
                # store in values to re-use variable on next read
                if var != mem_var:
                    mem_var = var
                    mem_values.invalidate()
                mem_values.write(offset, size, instr[:1], can_overlap=False)
        instrs_new.append(instr)
    instrs = instrs_new

    # remove dead writes
    instrs_new = []
    for i, instr in enumerate(instrs):
        if i not in dead_instrs:
            instrs_new.append(instr)
    return instrs_new


def sa_dead_code_elim(instrs, useful_regs):
    instrs_new = []
    tainted_vars = set()
    # find vars which write to registers
    for instr in instrs:
        if not instr[1].endswith(']=') and is_var(instr[0]):
            if instr[0] in useful_regs:
                tainted_vars.add(instr[0])
    # find vars which write to memory
    for instr in instrs:
        if instr[1].endswith(']='):
            for part in instr:
                if is_var(part):
                    tainted_vars.add(part)
    # find vars which assign to a tainted var by working backwards
    for instr in reversed(instrs):
        if not instr[1].endswith(']=') and instr[0] in tainted_vars:
            for part in instr[2:]:
                if is_var(part):
                    tainted_vars.add(part)
    # only include instructions which write to tainted vars
    for instr in instrs:
        if instr[0] in tainted_vars or isinstance(instr[0], int):
            instrs_new.append(instr)
    return instrs_new


def block_simplify(block, useful_regs=None):
    instrs, cond = block.instrs, block.condition
    useful_regs = useful_regs or (
        'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip',
        'cf', 'pf', 'af', 'zf', 'sf', 'tf', 'df', 'of', *((cond,) if cond else ())
    )
    instrs, var_map_ssa = sa_to_ssa(instrs)
    useful_regs = [var_map_ssa[reg] for reg in useful_regs if reg in var_map_ssa]
    while True:
        prev_len = len(instrs)
        instrs = sa_expr_simp(instrs)
        instrs = sa_common_subexpr(instrs)
        instrs = sa_sub_assign_retrieve(instrs)
        instrs = sa_copy_propagate(instrs)
        instrs = sa_const_fold(instrs)
        instrs = sa_mem_elim(instrs)
        instrs = sa_dead_code_elim(instrs, useful_regs)
        if len(instrs) == prev_len:
            break
    instrs, var_map_sa = ssa_to_sa(instrs)
    block.instrs = instrs
    cond = var_map_ssa.get(cond, cond)
    cond = var_map_sa.get(cond, cond)
    block.condition = cond
