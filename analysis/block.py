from collections import defaultdict

__all__ = ['simplify_block', 'sa_pprint']


def is_var(name):
    return isinstance(name, str) and str.isidentifier(name)


def esil_to_sa(instrs):
    '''
    Convert to sa form: (dest, assign_op, ...src).
    '''
    instrs = [part for instr in instrs for part in instr.split(',')]
    instrs_new = []
    instr_stack = []
    tmp_num = 0
    for instr in instrs:
        if str.isdecimal(instr):
            instr_stack.append(int(instr))
        elif instr.startswith('0x'):
            instr_stack.append(int(instr, 16))
        elif instr == '$0':
            instr_stack.append(0)
        elif instr == '$1':
            instr_stack.append(1)
        elif instr.startswith('$'):
            # esil register
            instr_stack.append(instr)
        elif instr in (
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
        ):
            # x86 register
            instr_stack.append(instr)
        elif instr == '=':
            instrs_new.append((instr_stack.pop(), instr, instr_stack.pop()))
        elif instr.startswith('=['):
            # write to memory
            dest = instr_stack.pop()
            src = instr_stack.pop()
            size = instr[2:-1]
            if not size and src == 'eip':
                size = 4
            instrs_new.append((dest, f'[{size}]=', src))
        elif instr in ('+=', '-=', '*=', '/=', '&=', '^='):
            dest = instr_stack.pop()
            src = instr_stack.pop()
            instrs_new.append((dest, '=', instr[0], dest, src))
        elif instr in ('+', '-', '*', '/', '&', '^', '=='):
            instrs_new.append((f'tmp_{tmp_num}', '=', instr, instr_stack.pop(), instr_stack.pop()))
            instr_stack.append(f'tmp_{tmp_num}')
            tmp_num += 1
        elif instr in ('[1]', '[2]', '[4]'):
            # read from memory
            instrs_new.append((f'tmp_{tmp_num}', f'={instr}', instr_stack.pop()))
            instr_stack.append(f'tmp_{tmp_num}')
            tmp_num += 1
        else:
            raise ValueError('instr', instr)
    return instrs_new


def sa_include_flag_deps(instrs):
    '''
    Include all register dependencies for flags.
    '''
    instrs_new = []
    i = 0
    while i < len(instrs):
        # append flag instructions first to avoid modification of register involved in computation of flag
        non_flag_instr = instrs[i]
        while i < len(instrs) - 1 and instrs[i + 1][0] in (
            'cf', 'pf', 'af', 'zf', 'sf', 'tf', 'df', 'of'
        ):
            if isinstance(instrs[i + 1][2], int):
                instrs_new.append(instrs[i + 1])
            else:
                instrs_new.append(instrs[i + 1] + non_flag_instr[2:])
            i += 1
        instrs_new.append(non_flag_instr)
        i += 1
    return instrs_new


def sa_include_subword_deps(instrs):
    '''
    Include all register dependencies for sub-word modifications, generated redundant code is optimized later.
    '''
    regdefs = [
        ('al', 'eax', 'l'), ('ah', 'eax', 'h'), ('ax', 'eax', 'x'),
        ('cl', 'ecx', 'l'), ('ch', 'ecx', 'h'), ('cx', 'ecx', 'x'),
        ('dl', 'edx', 'l'), ('dh', 'edx', 'h'), ('dx', 'edx', 'x'),
        ('bl', 'ebx', 'l'), ('bh', 'ebx', 'h'), ('bx', 'ebx', 'x'),
        ('sp', 'esp', 'x'),
        ('bp', 'ebp', 'x'),
        ('si', 'esi', 'x'),
        ('di', 'edi', 'x'),
    ]
    instrs_new = []
    for instr in instrs:
        for subreg, reg, op in regdefs:
            if subreg in instr[2:]:
                instrs_new.append((subreg, f'={op}', reg))
        instrs_new.append(instr)
        for subreg, reg, op in regdefs:
            if subreg == instr[0]:
                instrs_new.append((reg, f'{op}=', subreg))
    return instrs_new


def sa_to_ssa(instrs):
    '''
    Convert to ssa form.
    '''
    instrs_new = []
    var_num = defaultdict(int)
    for instr in instrs:
        parts_new = [instr[0], instr[1]]
        for part in instr[2:]:
            if is_var(part) and not part.startswith('tmp'):
                parts_new.append(f'{part}_{var_num[part]}')
            else:
                parts_new.append(part)
        part = instr[0]
        if is_var(part) and not part.startswith('tmp'):
            if not instr[1].endswith(']='):
                var_num[part] += 1
            parts_new[0] = f'{part}_{var_num[part]}'
        instrs_new.append(tuple(parts_new))
    return instrs_new


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
        if len(instr) == 3 and instr[1] == 'x=':
            var_map[(instr[0], 'x')] = instr[2]
        if len(instr) == 3 and instr[1] == '=x' and (instr[2], 'x') in var_map:
            var_map[instr[0]] = var_map[(instr[2], 'x')]
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
    conservative and don't assume register bounds.
    '''
    # track memory accesses and replace known memory values
    instrs_new = []
    var_map = {}  # maps `r2` to `(r1, 5)` if we have `r2 = r1 + 5`
    mem_var = None  # current var memory values are based upon
    mem_values = defaultdict(dict)  # {(offset, size): value}
    mem_instrs = defaultdict(dict)  # {(var_, offset, size): instr_i}, eliminates dead writes
    dead_instrs = set()
    for i, instr in enumerate(instrs):
        if instr[1] == '=' and instr[2] in ('+', '-') and isinstance(instr[4], int):
            var_map[instr[0]] = (instr[3], instr[4] if instr[2] == '+' else -instr[4])
        elif instr[1].endswith(']='):
            var = instr[0]
            var, offset = (None, var) if isinstance(var, int) else var_map.get(var, (var, 0))
            size = int(instr[1][1:-2])
            if var == mem_var:
                # invalidate value cache which overlaps
                for cache_offset, cache_size in list(mem_values):
                    if offset < cache_offset + cache_size and cache_offset < offset + size:
                        mem_values.pop((cache_offset, cache_size))
            else:
                # invalidate value cache since var has changed
                mem_var = var
                mem_values.clear()
            # check for dead writes and store new value
            if (var, offset, size) in mem_instrs:
                dead_instrs.add(mem_instrs[(var, offset, size)])
            mem_instrs[(var, offset, size)] = i
            mem_values[(offset, size)] = instr[2:]
        elif instr[1].startswith('=[') and len(instr) == 3:
            var = instr[2]
            var, offset = (None, var) if isinstance(var, int) else var_map.get(var, (var, 0))
            size = int(instr[1][2:-1])
            if var == mem_var and (offset, size) in mem_values:
                # we know the value, so don't need to read from memory
                instr = (instr[0], '=') + mem_values[(offset, size)]
            else:
                # we don't know the value, writes which could have written to this are useful
                for write_var, write_offset, write_size in list(mem_instrs):
                    if write_var != var or (offset < write_offset + write_size and write_offset < offset + size):
                        mem_instrs.pop((write_var, write_offset, write_size))
                # store in values to re-use variable on next read
                if var != mem_var:
                    mem_var = var
                    mem_values.clear()
                mem_values[(offset, size)] = (instr[0],)
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
    tainted_vars_map = {}
    for instr in instrs:
        if not instr[1].endswith(']=') and is_var(instr[0]):
            tainted_var = instr[0].split('_')[0]
            if tainted_var in useful_regs:
                tainted_vars_map[tainted_var] = instr[0]
    tainted_vars.update(tainted_vars_map.values())
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
        if instr[1].endswith(']=') or instr[0] in tainted_vars:
            instrs_new.append(instr)
    return instrs_new


def sa_pprint(instrs):
    instrs_new = []
    for instr in instrs:
        parts = [f'0x{part:08x}' if isinstance(part, int) else part for part in instr]
        arity = len(parts) - 3
        if arity == 0:
            instrs_new.append(f'{parts[0]} {parts[1]} {parts[2]}')
        elif arity == 1:
            instrs_new.append(f'{parts[0]} {parts[1]} {parts[2]}{parts[3]}')
        elif arity == 2:
            instrs_new.append(f'{parts[0]} {parts[1]} {parts[3]} {parts[2]} {parts[4]}')
        else:
            instrs_new.append(f'{parts[0]} {parts[1]} {parts[2]}({", ".join(parts[3:])})')
    return '\n'.join(instrs_new)


def simplify_block(block):
    '''
    Simplifies a block. A block is assumed to have no branches.
    '''
    # remove branch instructions
    instrs = block.instrs
    instrs = [instr for instr in instrs if '?{' not in instr]
    instrs = esil_to_sa(instrs)
    instrs = sa_include_flag_deps(instrs)
    instrs = sa_include_subword_deps(instrs)
    instrs = sa_to_ssa(instrs)
    while True:
        prev_len = len(instrs)
        instrs = sa_expr_simp(instrs)
        instrs = sa_common_subexpr(instrs)
        instrs = sa_copy_propagate(instrs)
        instrs = sa_const_fold(instrs)
        instrs = sa_mem_elim(instrs)
        instrs = sa_dead_code_elim(instrs, (
            'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip',
            'cf', 'pf', 'af', 'zf', 'sf', 'tf', 'df', 'of',
        ))
        if len(instrs) == prev_len:
            break
    block.instrs = instrs
