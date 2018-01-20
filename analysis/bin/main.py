import json
from json import JSONEncoder

import r2pipe

from analysis.block import Block, block_simplify
from analysis.constraint import DisjunctConstConstraint
from analysis.emu import update_radare_state
from analysis.extract import extract_funcs
from analysis.func import Function, func_simplify


def simplify_funcs(funcs):
    # simplify func
    for func, con in funcs.values():
        func_simplify(func)

    # simplify blocks
    for func, con in funcs.values():
        for block in func.block.dfs():
            block_simplify(block)


class FuncEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Function):
            return obj.__dict__
        elif isinstance(obj, Block):
            blocks = list(obj.dfs())
            return {id(block): {
                'addr_sizes': sorted(block.addr_sizes),
                'text': str(block),
                'children': [id(child) for child in block.children],
            } for block in blocks}
        return super().default(obj)


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

        # chain code together
        list(funcs_1[0x00401D6C][0].block.dfs())[-1].children = (funcs_3.pop(0x00401DC7)[0].block,)

        # simplify
        simplify_funcs(funcs_1)

        # export to visualize
        with open('../visualize/build/data.json', 'w') as sr:
            json.dump({
                'start': 0x401BB4,
                'end': 0x4046DB,
                'funcs': {addr: func for addr, (func, con) in funcs_1.items()},
            }, sr, cls=FuncEncoder)

    finally:
        r.quit()


if __name__ == '__main__':
    main()
