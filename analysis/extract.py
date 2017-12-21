from copy import deepcopy

from analysis.block import Block
from analysis.constraint import DisjunctConstConstraint
from analysis.func import ESILToFunc, Function


class FuncExtract:
    def __init__(self, r, start_addr, funcs, constraint, end_addrs):
        self.r = r
        self.start_addr = start_addr
        self.funcs = funcs
        self.start_constraint = constraint
        self.end_constraint = DisjunctConstConstraint()
        self.end_addrs = set(end_addrs)
        self.initial_vars = {}

        # part is the block index within an instruction, so we know if we visited the start of a block before
        self.block_to_constraint = {}  # {block: constraint}
        self.block_to_addrp = {}  # {(block, block_i): (addr, part)}
        self.addrp_to_block = {}  # {(addr, part): (block, block_i)}
        self.edges = set()  # [(parent, child)]
        self.stack = []  # [block]

    def _extract_esil(self, addr):
        # update eip so the instruction is more complete for conditional jmps and call
        res = self.r.cmdj(f'pdj 1 @ {addr}')[0]
        return f'{addr + res["size"]},eip,=,{res["esil"]}', addr, res['size']

    def _block_append_instr(self, block, addr):
        func = ESILToFunc(*self._extract_esil(addr)).convert()
        block.merge(func.block)
        for part, cur_block in enumerate(block.dfs()):
            if cur_block.instrs:
                block_i = len(block.instrs) - len(func.block.instrs) if part == 0 else 0
                self.block_to_addrp[(cur_block, block_i)] = (addr, part)
                self.addrp_to_block[(addr, part)] = (cur_block, block_i)

    def _extract_block(self, part, block):
        con = deepcopy(self.block_to_constraint[block])
        block_i = 0
        while True:
            addr = con.const_cons[0].vars.get('eip', None)
            is_part_end = block_i == len(block.instrs)

            # reset part to 0
            if is_part_end:
                part = 0

            # address ends analysis
            if is_part_end and not isinstance(addr, int) or addr in self.end_addrs:
                self.end_constraint.widen(con)
                break

            # we have a conditional jmp
            if is_part_end and block.condition:
                # explore remaining code first before exploring jmp
                for child, val in zip(block.children, (True, False)):
                    cur_con = deepcopy(con)
                    cur_con.solve(block.condition, val)
                    if cur_con.const_cons:
                        cur_con.finalize()
                        self.block_to_constraint[child] = cur_con
                        self.edges.add((block, child))
                        self.stack.append((self.block_to_addrp.get((child, 0), (None, 0))[1], child))
                break

            # address is already found (can happen due to jmps or constraint propagation)
            if (block_i == 0 or is_part_end) and block.instrs and (addr, part) in self.addrp_to_block:
                goto_block, block_i = self.addrp_to_block[(addr, part)]
                if block_i:
                    # split block
                    lower_half = goto_block.split(block_i, self.block_to_addrp[(goto_block, block_i)][0])

                    # update addrp maps
                    for i in range(len(lower_half.instrs)):
                        if (goto_block, block_i + i) in self.block_to_addrp:
                            addrp = self.block_to_addrp.pop((goto_block, block_i + i))
                            self.block_to_addrp[(lower_half, i)] = addrp
                            self.addrp_to_block[addrp] = lower_half, i

                    # find lower_half constraints
                    cur_con = deepcopy(self.block_to_constraint[goto_block])
                    for instr in goto_block.instrs:
                        cur_con.step(instr)
                    self.block_to_constraint[lower_half] = cur_con

                    # update block vars
                    goto_block.children = (lower_half,)
                    self.edges.add((goto_block, lower_half))
                    if block == goto_block:
                        block = lower_half
                    goto_block = lower_half

                # address found due to jmp
                if is_part_end:
                    block.children = (goto_block,)
                    self.edges.add((block, goto_block))

                # update constraints
                goto_con = self.block_to_constraint[goto_block]
                prev_goto_con = deepcopy(goto_con)
                goto_con.widen(con)
                if goto_con != prev_goto_con:
                    con = deepcopy(goto_con)
                    for instr in goto_block.instrs:
                        con.step(instr)
                    block, block_i = goto_block, len(goto_block.instrs)
                    continue
                break

            # add new instruction
            if is_part_end:
                self._block_append_instr(block, addr)

            # # instruction is a call to api
            # matches = re.match(r'(\d+),eip,=,eip,4,esp,-=,esp,=\[\],(\d+),eip,=', instr)
            # if matches:
            #     ret_addr, call_addr = matches.group(1), matches.group(2)
            #     matches = re.match(r'(0x\d+),\[\],eip,=', self.r.cmdj(f'pdj 1 @ {call_addr}')[0]['esil'])
            #     if matches:
            #         api_addr = matches.group(1)
            #         matches = re.match(r'sym\.imp\.(\S+)_(\S+)$', self.r.cmd(f'fd {api_addr}'))
            #         if matches:
            #             # end current block to aid in de-obfuscation
            #             lib_name, api_name = matches.group(1), matches.group(2)
            #             state.step_api_jmp(lib_name, api_name)
            #             self._stack_append(int(ret_addr), state)
            #             block.children = [int(ret_addr)]
            #             break

            # instruction is a call to a proc
            # function was already analyzed

            # instruction is not special, so just step
            con.step(block.instrs[block_i])
            block_i += 1

    def extract(self):
        block, con = Block(), self.start_constraint
        con.step(('eip', '=', self.start_addr))
        self.block_to_constraint[block] = deepcopy(con)
        self.stack.append((0, block))
        while self.stack:
            self._extract_block(*self.stack.pop())
        for parent in block.dfs():
            parent.children = tuple(child for child in parent.children if (parent, child) in self.edges)
        self.funcs[self.start_addr] = Function(self.start_addr, block), self.end_constraint


def extract_funcs(r, addr, constraint, end_addrs=()):
    funcs = {}
    FuncExtract(r, addr, funcs, constraint, end_addrs).extract()
    return funcs
