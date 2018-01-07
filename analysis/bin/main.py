import r2pipe

from analysis.block import block_simplify
from analysis.constraint import DisjunctConstConstraint
from analysis.emu import update_radare_state
from analysis.extract import extract_funcs
from analysis.func import func_simplify


def process_funcs(funcs):
    # simplify func
    for func, con in funcs.values():
        func_simplify(func)

    # de-obfuscate blocks
    for func, con in funcs.values():
        for block in func.block.dfs():
            block_simplify(block)

    # pretty-print
    for func, con in funcs.values():
        print(f'sub_{func.addr:08x}')
        for block in func.block.dfs():
            print(f'block_{min(block.addr_sizes)[0]:08x}')
            print(block)
            if block.children:
                print('children: ' + ' '.join(f'block_{min(child.addr_sizes)[0]:08x}' for child in block.children))
            print()


def main():
    r = r2pipe.open('../../ReverseMe#8 by lena151.exe')

    try:
        # enable emu writes for decryption code
        r.cmd('aei')
        r.cmd('aeim')
        r.cmd('e asm.emuwrite=true')
        r.cmd('e io.cache=true')
        initial_vars = r.cmdj(f'aerj')

        # first decrypt loop
        funcs_0 = extract_funcs(r, 0x00401BB4, DisjunctConstConstraint.from_oep(), end_addrs=(0x00401D6C,))
        update_radare_state(r, funcs_0[0x00401BB4][1], initial_vars)
        r.cmd('e.aecu 0x00401D6C')

        # code
        funcs_1 = extract_funcs(r, 0x00401D6C, funcs_0[0x00401BB4][1], end_addrs=(0x00401D77,))

        # second decrypt loop
        funcs_2 = extract_funcs(r, 0x00401D77, funcs_1[0x00401D6C][1], end_addrs=(0x00401DC7,))
        update_radare_state(r, funcs_2[0x00401D77][1], initial_vars)
        r.cmd('e.aecu 0x00401DC7')

        # code
        funcs_3 = extract_funcs(r, 0x00401DC7, funcs_2[0x00401D77][1], end_addrs=(0x00401E73,))

        # pretty-print
        funcs_1[0x00401D6C][0].block.merge(funcs_3.pop(0x00401DC7)[0].block)
        process_funcs(funcs_1)

    finally:
        r.quit()


if __name__ == '__main__':
    main()
