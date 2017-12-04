import r2pipe

from analysis.block import sa_pprint, simplify_block
from analysis.extract import FuncsExtract
from analysis.func import simplify_func


def main():
    r = r2pipe.open('../../ReverseMe#8 by lena151.exe')

    try:
        # enable emu writes for self-modifying code
        r.cmd('e asm.emuwrite=true')
        r.cmd('e io.cache=true')

        # extract funcs
        funcs = FuncsExtract(r).extract_funcs(
            r.cmdj('aerj')['eip'],
            assume_new=list(range(0x401BB4, 0x401D6C)) + list(range(0x401D77, 0x401DC7)),
            end_addrs=(0x00401E73,)
        )

        # simplify func
        for func in funcs:
            simplify_func(func)

        # de-obfuscate blocks
        for func in funcs:
            for block in func.blocks.values():
                simplify_block(block)

        # pretty-print
        for func in funcs:
            print(f'sub_{func.addr:08x}')
            for block_addr, block in sorted(func.blocks.items()):
                print(f'block_{block_addr:08x}')
                print(sa_pprint(block.instrs))
                if block.condition:
                    flag, is_negated = block.condition
                    true_addr, false_addr = block.children[::-1] if is_negated else block.children
                    print(f'{flag} ? {true_addr:08x} : {false_addr:08x}')
                elif block.children:
                    print(f'{block.children[0]:08x}')
                print()

    finally:
        r.quit()


if __name__ == '__main__':
    main()
