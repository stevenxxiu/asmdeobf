import re

import r2pipe

from analysis.block import simplify_block, sa_pprint


class Block:
    def __init__(self, addrs=None, instrs=None, children=None):
        self.addrs = addrs or []
        self.instrs = instrs or []
        self.children = children or []

    def __eq__(self, other):
        if isinstance(self, other.__class__):
            return self.__dict__ == other.__dict__
        return False


def extract_esil(r, addr):
    '''
    Get esil at addr. Requires `e asm.esil=true`.
    '''
    # update eip to facilitate analysis of conditional jmps and call
    res = r.cmdj(f'pdj 1 @ {addr}')[0]
    return f'{addr + res["size"]},eip,=,{res["esil"]}'


def extract_func(r, start_addr, funcs, is_oep_func=False):
    addr_map = {}  # {addr: (block, i)}
    stack = [(start_addr, {})]  # [(addr, flags)]
    is_oep_block = is_oep_func

    while stack:
        cur_addr, flag_vals = stack.pop()

        # if address is already found (through conditional jmps) then split block in two
        if cur_addr in addr_map:
            block, i = addr_map[cur_addr]
            new_block = Block()
            new_block.addrs = block.addrs[:i]
            new_block.instrs = block.instrs[:i]
            for j, addr in enumerate(new_block.addrs):
                addr_map[addr] = (new_block, j)
            new_block.children = [block]
            block.addrs = block.addrs[i:]
            block.instrs = block.instrs[i:]
            for j, addr in enumerate(block.addrs):
                addr_map[addr] = (block, j)
            continue

        block = Block()

        # emulate block
        r.cmd(f's {cur_addr}')
        r.cmd('aei')
        r.cmd('aeim')
        r.cmd('aeip')

        # update emulator flag values
        for flag, val in flag_vals.items():
            if val is not None:
                r.cmd(f'aer {flag}={val}')

        while True:
            cur_addr = int(r.cmd('aer eip'), 16)
            if cur_addr == 0 or cur_addr == 0x00401E6E:
                break
            instr = extract_esil(r, cur_addr)
            addr_map[cur_addr] = (block, len(block.instrs))
            block.addrs.append(cur_addr)
            block.instrs.append(instr)

            # update certain flag values for conditional branches
            for flag, value in re.findall(r'\b(\wf),=(\$\w+)', instr):
                flag_vals[flag] = 0 if value == '$0' else 1 if value == '$1' else None
            if re.match(r'\d+,eip,=,(\w+),\1,\^=', instr):
                flag_vals['zf'] = 0

            # check if we have a conditional jmp
            matches = re.match(r'(\d+),eip,=,(\wf),(!,)?\?{,(\d+),eip,=,}', instr)
            if matches and not is_oep_block:
                flag = matches.group(2)
                is_negated = bool(matches.group(3))
                if flag_vals.get(flag, None) is None:
                    stack.append((int(matches.group(1)), {flag: not is_negated}))
                    stack.append((int(matches.group(4)), {flag: is_negated}))
                    break

            # check if instruction is a call to api
            matches = re.match(r'(\d+),eip,=,eip,4,esp,-=,esp,=\[\],\d+,eip,=', instr)
            if matches:
                call_addr = int(instr.split(',')[-3])
                if re.match(r'\d+,eip,=,0x[\d0-f]+,\[\],eip,=', extract_esil(r, call_addr)):
                    # end current block to aid in de-obfuscation
                    stack.append((int(matches.group(1)), {}))
                    break

            # check if instruction is a call to a proc
            # check if function was already analyzed

            r.cmd('aes')

    block = addr_map[start_addr][0]
    funcs[start_addr] = block
    return block


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
