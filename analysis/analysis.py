from collections import defaultdict

import r2pipe

x86_regs = (
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
)


def pd_extract_esil(s):
    '''
    Extracts esil string from a line of disasm (from pd command). Requires `e asm.esil=true`.
    '''
    return s.split('\n')[-1][43:].split(';')[0]


def esil_to_sa(instrs):
    '''
    Convert to sa form: (dest, assign_op, ...src).
    '''
    instrs = [part for instr in instrs for part in instr.strip().split(',')]
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
        elif instr in x86_regs:
            # x86 register
            instr_stack.append(instr)
        elif instr in ('=', '=[]', '=[1]', '=[2]', '=[4]'):
            instrs_new.append((instr_stack.pop(), instr, instr_stack.pop()))
        elif instr in ('+=', '-=', '*=', '/=', '&=', '^='):
            stack_1 = instr_stack.pop()
            stack_2 = instr_stack.pop()
            instrs_new.append((stack_1, '=', instr[0], stack_1, stack_2))
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
    reg_num = defaultdict(int)
    for instr in instrs:
        parts_new = [instr[0], instr[1]]
        for part in instr[2:]:
            if part in x86_regs:
                parts_new.append(f'{part}_{reg_num[part]}')
            else:
                parts_new.append(part)
        part = instr[0]
        if part in x86_regs:
            if not instr[1].startswith('=['):
                reg_num[part] += 1
            parts_new[0] = f'{part}_{reg_num[part]}'
        instrs_new.append(tuple(parts_new))
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
    # XXX constant propogation
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
            instrs.append(pd_extract_esil(r.cmd(f'pd 1 @ {r.cmd("aer eip")}')))
            r.cmd('aes')
        print(simplify_block(instrs))
    finally:
        r.quit()


if __name__ == '__main__':
    main()
