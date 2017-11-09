import r2pipe


def pd_esil(s):
    # requires `e asm.esil=true`
    return s.split('\n')[-1][43:].split(';')[0]


def simplify_block(instrs):
    '''
    Simplifies a block. A block is assumed to have no branches.
    '''
    # remove branch instructions
    instrs = [instr for instr in instrs if '?{' not in instr]

    # convert to sa form
    instrs = [part for instr in instrs for part in instr.strip().split(',')]
    instr_stack = []
    instrs_sa = []
    tmp_num = 0
    for instr in instrs:
        if str.isdecimal(instr):
            instr_stack.append(int(instr))
        elif instr.startswith('0x'):
            instr_stack.append(int(instr, 16))
        elif instr in (
                'al', 'ax', 'eax',
                'cl', 'cx', 'ecx',
                'dl', 'dx', 'edx',
                'bl', 'bx', 'ebx',
                'sp', 'esp',
                'bp', 'ebp',
                'si', 'esi',
                'di', 'edi',
                'eip',
                'cf', 'pf', 'af', 'zf', 'sf', 'tf', 'df', 'of',
                '$0', '$1', '$b4', '$b16', '$c31', '$o', '$p', '$s', '$z',
        ):
            instr_stack.append(instr)
        elif instr in ('=', '=[]', '=[1]', '=[2]', '=[4]'):
            instrs_sa.append((instr_stack.pop(), instr, instr_stack.pop()))
        elif instr in ('+=', '-=', '*=', '/=', '&=', '^='):
            stack_1 = instr_stack.pop()
            stack_2 = instr_stack.pop()
            instrs_sa.append((stack_1, '=', stack_1, instr[0], stack_2))
        elif instr in ('+', '-', '*', '/', '&', '^', '=='):
            instrs_sa.append((f'tmp_{tmp_num}', '=', instr_stack.pop(), instr, instr_stack.pop()))
            instr_stack.append(f'tmp_{tmp_num}')
            tmp_num += 1
        elif instr in ('[1]', '[2]', '[4]'):
            instrs_sa.append((f'tmp_{tmp_num}', f'={instr}', instr_stack.pop()))
            instr_stack.append(f'tmp_{tmp_num}')
            tmp_num += 1
        else:
            raise ValueError(instr)
    instrs = instrs_sa

    # process shortened forms of the full register (with custom ops like =1, =2, =4)

    # convert to ssa form

    # constant propogation

    # pretty print
    return '\n'.join(' '.join(
        (f'0x{part:08x}' if isinstance(part, int) else part for part in instr)
    ) for instr in instrs)


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
            instrs.append(pd_esil(r.cmd(f'pd 1 @ {r.cmd("aer eip")}')))
            r.cmd('aes')
        print(simplify_block(instrs))
    finally:
        r.quit()


if __name__ == '__main__':
    main()
