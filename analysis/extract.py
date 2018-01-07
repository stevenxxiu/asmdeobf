import re
from copy import deepcopy

from bidict import bidict
from ordered_set import OrderedSet

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
        self.addr_to_block = bidict()  # {(addr, part): (block, block_i)}
        self.visited = set()  # {block}

    def _block_append_instr(self, block, addr):
        res = self.r.cmdj(f'pdj 1 @ {addr}')[0]
        func = ESILToFunc(res['esil'], addr, res['size']).convert()
        # remove children of blocks which modify eip, so that branches don't end with same block
        for cur_block in func.block.dfs():
            if any(instr[:2] == ('eip', '=') for instr in cur_block.instrs):
                cur_block.children = ()
        # update eip since radare does not include this
        func.block.instrs.insert(0, ('eip', '=', addr + res['size']))
        self.addr_to_block[addr] = (block, len(block.instrs))
        block.merge(func.block)

    def _explore_block(self, block, propagate_blocks):
        '''
        Add instructions to block until we hit the end or a previous instruction.
        '''
        con = deepcopy(self.block_to_constraint[block])
        block_i = 0
        while True:
            # run instruction
            for instr in block.instrs[block_i:]:
                con.step(instr)
            block_i = len(block.instrs)
            addr = con.const_cons[0].vars.get('eip', None)

            # instruction is an api call
            if len(block.instrs) >= 2 and block.instrs[-1] == ('eip', '=', 'tmp_0'):
                api_addr = block.instrs[-2][2]
                block.instrs = block.instrs[:-2]
                block.call = re.match(r'sym\.imp\.(\S+)_(\S+)$', self.r.cmd(f'fd {api_addr}')).groups()
                block.children = (Block(),)
                propagate_blocks.append((block, len(block.instrs), con))
                return

            # address ends block
            if block.children or (not isinstance(addr, int) or addr in self.end_addrs):
                propagate_blocks.append((block, len(block.instrs), con))
                return

            # address is already found (can happen due to jmps)
            if addr in self.addr_to_block:
                goto_block, block_i = self.addr_to_block[addr]
                if block_i:
                    lower_half = goto_block.split(block_i, self.addr_to_block.inv[(goto_block, block_i)])
                    for i in range(len(lower_half.instrs)):
                        key = (goto_block, block_i + i)
                        if key in self.addr_to_block.inv:
                            self.addr_to_block.inv[(lower_half, i)] = self.addr_to_block.inv.pop(key)
                    goto_block.children = (lower_half,)
                    propagate_blocks.append((goto_block, 0, self.block_to_constraint[goto_block]))
                    self.block_to_constraint[goto_block] = DisjunctConstConstraint()
                    for i, (cur_block, cur_block_i, cur_con) in enumerate(propagate_blocks):
                        if cur_block == goto_block and cur_block_i >= len(goto_block.instrs):
                            propagate_blocks[i] = (lower_half, cur_block_i - len(goto_block.instrs), cur_con)
                    self.visited.add(lower_half)
                    if block == goto_block:
                        block = lower_half
                    goto_block = lower_half
                block.children = (goto_block,)
                propagate_blocks.append((goto_block, 0, con))
                return

            # append new instruction
            self._block_append_instr(block, addr)

    def _propagate_constraints(self, propagate_blocks):
        '''
        Widen constraints in the visited parts of the cfg s.t. they converge.
        '''
        explore_blocks = OrderedSet()
        while propagate_blocks:
            block, block_i, con = propagate_blocks.pop(0)
            if block_i == 0:
                if block in self.block_to_constraint:
                    prev_con = self.block_to_constraint[block]
                    con.widen(prev_con)
                    con.finalize()
                    if con == prev_con:
                        continue
                else:
                    con.finalize()
                self.block_to_constraint[block] = deepcopy(con)
            if block not in self.visited:
                explore_blocks.add(block)
                continue
            for instr in block.instrs[block_i:]:
                con.step(instr)
            for i, child in enumerate(block.children):
                cur_con = deepcopy(con)
                if block.call:
                    cur_con.step_api_jmp(*block.call)
                if block.condition:
                    # explore remaining code first before exploring jmp
                    cur_con.solve(block.condition, [True, False][i])
                if cur_con.const_cons:
                    propagate_blocks.append((child, 0, cur_con))
            if block in self.visited and not block.children:
                self.end_constraint.widen(con)
                self.end_constraint.finalize()
        return explore_blocks

    def extract(self):
        block, con = Block(), self.start_constraint
        con.step(('eip', '=', self.start_addr))
        self.block_to_constraint[block] = con
        explore_blocks, propagate_blocks = [block], []
        while explore_blocks:
            for cur_block in explore_blocks:
                self._explore_block(cur_block, propagate_blocks)
                self.visited.add(cur_block)
            explore_blocks = self._propagate_constraints(propagate_blocks)
        for parent in block.dfs():
            parent.children = tuple(child for child in parent.children if child in self.visited)
        self.funcs[self.start_addr] = Function(self.start_addr, block), self.end_constraint


def extract_funcs(r, addr, constraint, end_addrs=()):
    funcs = {}
    FuncExtract(r, addr, funcs, constraint, end_addrs).extract()
    return funcs
