import r2pipe

from analysis.simplify import simplify_block


def pd_extract_esil(s):
    '''
    Extracts esil string from a line of disasm (from pd command). Requires `e asm.esil=true`.
    '''
    return s.split('\n')[-1][43:].split(';')[0].strip()


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
