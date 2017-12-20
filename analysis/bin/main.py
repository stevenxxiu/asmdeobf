import r2pipe

from analysis.block import block_simplify
from analysis.constraint import ConstConstraint
from analysis.emu import update_radare_state
from analysis.extract import extract_funcs
from analysis.func import func_simplify


def process_funcs(funcs):
    # simplify func
    for func in funcs:
        func_simplify(func)

    # de-obfuscate blocks
    for func in funcs:
        for block in func.block.dfs():
            block_simplify(block)

    # pretty-print
    for func in funcs:
        print(f'sub_{func.addr:08x}')
        for block in func.block.dfs():
            print(f'block_{block_addr:08x}')
            print(block)
            if block.condition:
                flag, is_negated = block.condition
                true_addr, false_addr = block.children[::-1] if is_negated else block.children
                print(f'{flag} ? {true_addr:08x} : {false_addr:08x}')
            elif block.children:
                print(f'{block.children[0]:08x}')
            print()


def main():
    r = r2pipe.open('../../ReverseMe#8 by lena151.exe')

    try:
        # enable emu writes for self-modifying code
        r.cmd('aei')
        r.cmd('aeim')
        r.cmd('e asm.emuwrite=true')
        r.cmd('e io.cache=true')
        initial_vars = r.cmdj(f'aerj')

        # first decrypt loop
        funcs = extract_funcs(r, 0x00401BB4, ConstConstraint.from_oep(), end_addrs=(0x00401D6C,))
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
