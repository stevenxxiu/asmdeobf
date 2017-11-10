from collections import defaultdict

import r2pipe


def pd_extract_esil(s):
    '''
    Extracts esil string from a line of disasm (from pd command). Requires `e asm.esil=true`.
    '''
    return s.split('\n')[-1][43:].split(';')[0].strip()


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
            instrs_new.append((f'tmp_{tmp_num}', f'={instr}', instr_stack.pop()))
            instr_stack.append(f'tmp_{tmp_num}')
            tmp_num += 1
        else:
            raise ValueError(instr)
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
    # replace a ^ a with 0
    instrs_new = []
    for instr in instrs:
        if instr[2] == '^' and instr[3] == instr[4]:
            instrs_new.append(instr[:2] + (0,))
        else:
            instrs_new.append(instr)
    instrs = instrs_new

    # simplify expressions involving a + 1, a - 1
    instrs_new = []
    var_map = {}
    for instr in instrs:
        if instr[2] in ('+', '-'):
            vars_ = []

            # replace constant vars
            for var_ in instr[3:]:
                if var_ in var_map and len(var_map[var_]) == 1:
                    var_ = var_map[var_][0]
                vars_.append(var_)
            instr = instr[:3] + tuple(vars_)

            # simplify expressions
            var_ = instr[3]
            if var_ in var_map and len(var_map[var_]) == 3 and isinstance(instr[4], int):
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

        # store simplified expression
        if instr[1] == '=':
            if len(instr) == 3 or (instr[2] in ('+', '-') and isinstance(instr[4], int)):
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
    This only copys variables and not expressions. Otherwise the following will not be simpler:
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


def simplify_block(instrs):
    '''
    Simplifies a block. A block is assumed to have no branches.
    '''
    # remove branch instructions
    instrs = [instr for instr in instrs if '?{' not in instr]
    instrs = esil_to_sa(instrs)
    instrs = sa_include_flag_deps(instrs)
    instrs = sa_include_subword_deps(instrs)
    instrs = sa_to_ssa(instrs)
    # XXX memory constant elimination
    instrs = sa_expr_simp(instrs)
    instrs = sa_common_subexpr(instrs)
    instrs = sa_copy_propagate(instrs)
    instrs = sa_dead_code_elim(instrs, (
        'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip',
        'cf', 'pf', 'af', 'zf', 'sf', 'tf', 'df', 'of',
    ))
    return sa_pprint(instrs)


def main():
    r = r2pipe.open('../../ReverseMe#8 by lena151.exe')

    try:
        # setup esil
        r.cmd('e asm.esil=true')

        # setup emu
        r.cmd('e asm.emuwrite=true')
        r.cmd('e io.cache=true')

        # emulate block at program start
        r.cmd('aei')
        r.cmd('aeim')
        r.cmd('aeip')

        instrs = []
        for i in range(106):
            eip = r.cmd('aer eip')
            if r.cmd(f'p8j 1 @ {eip}') == '[232]':
                # add additional esil instruction for call
                instrs.append(f'{int(eip, 16) + 5},eip,=')
            instrs.append(pd_extract_esil(r.cmd(f'pd 1 @ {eip}')))
            r.cmd('aes')
        print(simplify_block(instrs))
    finally:
        r.quit()


if __name__ == '__main__':
    main()
