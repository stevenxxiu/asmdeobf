import re

import r2pipe

from analysis.block import simplify_block, sa_pprint


def extract_esil(r, addr):
    '''
    Get esil at addr. Requires `e asm.esil=true`.
    '''
    res = ''
    if r.cmd(f'p8j 1 @ {addr}') == '[232]':
        # need to update eip before call
        res = f'{addr + 5},eip,=,'
    pd = r.cmd(f'pd 1 @ {addr}')
    res += pd.split('\n')[-1][43:].split(';')[0].strip()
    return res


def extract_func(r, start_addr, init_block, funcs):
    blocks = []
    cur_addr = start_addr
    while True:
        # emulate block
        r.cmd(f's {cur_addr}')
        r.cmd('aei')
        r.cmd('aeim')
        r.cmd('aeip')
        instrs = []
        while True:
            cur_addr = int(r.cmd('aer eip'), 16)
            esil = extract_esil(r, cur_addr)
            instrs.append(esil)

            # check if jump is conditional
            if not init_block:
                if False:
                    raise NotImplementedError('conditional jmp')

            # check if instruction is a call to api
            if re.match(r'\d+,eip,=,eip,4,esp,-=,esp,=\[\],\d+,eip,=', esil):
                call_addr = int(esil.split(',')[-3])
                if extract_esil(r, call_addr) == 'eip,=':
                    # add call as new block to aid de-obfuscation
                    blocks.append(instrs)
                    # go to return address
                    cur_addr += 5
                    break

            # check if instruction is a call to a proc

            # check if esp is the same, i.e. function has returned
            if cur_addr == 0x00401DFB:
                funcs[start_addr] = blocks
                return
            r.cmd('aes')


def extract_funcs(r, addr):
    funcs = {}
    extract_func(r, addr, True, funcs)
    return funcs


def main():
    r = r2pipe.open('../../ReverseMe#8 by lena151.exe')

    try:
        # setup esil
        r.cmd('e asm.esil=true')

        # setup emu
        r.cmd('e asm.emuwrite=true')
        r.cmd('e io.cache=true')

        # extract funcs
        funcs = extract_funcs(r, int(r.cmd("aer eip"), 16))

        # de-obfuscate blocks
        for func in funcs.values():
            for i, block in enumerate(func):
                func[i] = simplify_block(block)

        # pretty-print
        for addr, func in sorted(funcs.items()):
            print(f'sub_{addr:08x}')
            for i, block in enumerate(func):
                print(f'block_{i}')
                print(sa_pprint(block))
                print()

    finally:
        r.quit()


if __name__ == '__main__':
    main()
