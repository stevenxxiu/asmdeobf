import r2pipe


def pd_esil(s):
    # requires `e asm.esil=true`
    return s.split('\n')[-1][43:].split(';')[0]

def main():
    r = r2pipe.open('../../ReverseMe#8 by lena151.exe')

    # setup esil
    r.cmd('e asm.esil=true')

    # setup emu
    r.cmd('e asm.emuwrite=true')
    r.cmd('e io.cache=true')

    # emulate block at program start
    r.cmd('aei')
    r.cmd('aeim')
    r.cmd('aeip')

    for i in range(107):
        print(pd_esil(r.cmd(f'pd 1 @ {r.cmd("aer eip")}')))
        r.cmd('aes')

    r.quit()


if __name__ == '__main__':
    main()
