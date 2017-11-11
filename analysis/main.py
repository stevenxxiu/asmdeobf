import re

import r2pipe

from analysis.block import simplify_block, sa_pprint


def extract_esil(r, addr):
    '''
    Get esil at addr. Requires `e asm.esil=true`.
    '''
    # update eip to facilitate analysis of conditional jmps and call
    res = r.cmdj(f'pdj 1 @ {addr}')[0]
    return f'{addr + res["size"]},eip,=,{res["esil"]}'


def extract_func(r, start_addr, funcs, oep_func=False):
    blocks = []
    cur_addr = start_addr
    while True:
        # emulate block
        r.cmd(f's {cur_addr}')
        r.cmd('aei')
        r.cmd('aeim')
        r.cmd('aeip')
        instrs = []
        flag_vals = {}
        while True:
            cur_addr = int(r.cmd('aer eip'), 16)
            instr = extract_esil(r, cur_addr)
            instrs.append(instr)

            # check if jump is actually conditional, if not oep block
            if not oep_func or blocks:
                for flag in re.findall(r'\b(\wf),=', instr):
                    flag_vals[flag] = None
                if re.match(r'\d+,eip,=,(\w+),\1,\^=', instr):
                    flag_vals['zf'] = 0
                matches = re.match(r'\d+,eip,=,(\wf),(!,)?\?{', instr)
                if matches:
                    is_conditional = True
                    flag = matches.group(1)
                    # flag is constant
                    if is_conditional and flag_vals.get(flag) is not None:
                        is_conditional = False
                    # jmp address is same regardless of flag
                    if is_conditional:
                        jmp_addrs = {}
                        for flag_val in True, False:
                            while True:
                                jmp_instr = extract_esil(r, cur_addr)
                                matches = re.match(r'(\d+),eip,=,(\wf),\?{,(\d+),eip,=,}', instr)


                    if is_conditional:
                        raise NotImplementedError('conditional jmp')

            # check if instruction is a call to api
            matches = re.match(r'(\d+),eip,=,eip,4,esp,-=,esp,=\[\],\d+,eip,=', instr)
            if matches:
                call_addr = int(instr.split(',')[-3])
                if re.match(r'\d+,eip,=,0x[\d0-f]+,\[\],eip,=', extract_esil(r, call_addr)):
                    # add call as new block to aid de-obfuscation
                    blocks.append(instrs)
                    # go to return address
                    cur_addr = int(matches.group(1))
                    break

            # check if instruction is a call to a proc
            # check if function was already analyzed

            # check if esp is the same, i.e. function has returned
            if cur_addr == 0x00401E6E:
                blocks.append(instrs)
                funcs[start_addr] = blocks
                return
            r.cmd('aes')


def extract_funcs(r, addr):
    funcs = {}
    extract_func(r, addr, funcs, True)
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
