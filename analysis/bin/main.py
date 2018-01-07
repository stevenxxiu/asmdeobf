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
        funcs = extract_funcs(r, 0x00401BB4, DisjunctConstConstraint.from_oep(), end_addrs=(0x00401D6C,))
        update_radare_state(r, funcs[0x00401BB4][1], initial_vars)
        r.cmd('e.aecu 0x00401D6C')

        # code
        funcs = extract_funcs(r, 0x00401D6C, funcs[0x00401BB4][1], end_addrs=(0x00401D77,))
        process_funcs(funcs)

        # second decrypt loop
        funcs = extract_funcs(r, 0x00401D77, funcs[0x00401D6C][1], end_addrs=(0x00401DC7,))
        update_radare_state(r, funcs[0x00401D77][1], initial_vars)
        r.cmd('e.aecu 0x00401DC7')

        # code
        funcs = extract_funcs(r, 0x00401DC7, funcs[0x00401D77][1], end_addrs=(0x00401E73,))
        process_funcs(funcs)

    finally:
        r.quit()


if __name__ == '__main__':
    main()
