import re

from expects.matchers import Matcher

from analysis.block import Block
from analysis.constraint import ConstConstraint
from analysis.func import Function

__all__ = ['to_blocks', 'to_func', 'eq_block', 'eq_func']


def to_blocks(block_defs):
    blocks = [Block(block_def.get('addr_sizes', set()), block_def.get('instrs', [])) for block_def in block_defs]
    for i, (block, block_dfs) in enumerate(zip(blocks, blocks[0].dfs())):
        if block is not block_dfs:
            raise ValueError(f'block {i} is not sorted via dfs (needed so eq_block errors make sense)')
    for block, block_def in zip(blocks, block_defs):
        block.condition = block_def.get('condition', None)
        block.children = tuple(blocks[i] for i in block_def.get('children', ()))
    return blocks


def to_func(addr, block_defs):
    return Function(addr, to_blocks(block_defs)[0])


def assert_msg(msg, value, expected):
    if value != expected:
        raise ValueError(msg, str(value), str(expected))


class eq_block(Matcher):
    def __init__(self, expected):
        self._expected = expected

    @staticmethod
    def _assert(self, expected):
        blocks, expected_blocks = list(self.dfs()), list(expected.dfs())
        assert_msg('# of blocks are different', len(blocks), len(expected_blocks))
        for i, (func_block, expected_block) in enumerate(zip(blocks, expected_blocks)):
            assert_msg(f'block {i} instrs are different', func_block.instrs, expected_block.instrs)
            assert_msg(f'block {i} addr_sizes are different', func_block.addr_sizes, expected_block.addr_sizes)
            assert_msg(
                f'block {i} condition is different', func_block.condition, expected_block.condition
            )
            func_children = tuple(blocks.index(block) for block in func_block.children)
            expected_children = tuple(expected_blocks.index(block) for block in expected_block.children)
            assert_msg(f'block {i} children are different', func_children, expected_children)

    def _match(self, block):
        try:
            self._assert(self._expected, block)
            return True, []
        except ValueError as e:
            return False, e.args


class eq_func(eq_block):
    @staticmethod
    def _assert(self, expected):
        assert_msg('addr is different', self.addr, expected.addr)
        eq_block._assert(self.block, expected.block)


class MockRadare:
    def __init__(self, instrs, base_addr):
        self.instrs = instrs
        self.base_addr = base_addr
        self.emu = ConstConstraint()
        for var in ConstConstraint.bits:
            self.emu.vars[var] = 0
        for i in range(0, 100, 4):
            self.emu.mem.values[(i, 4)] = 0

    def cmd(self, cmd):
        matches = re.match(r's (\d+)', cmd)
        if matches:
            self.emu.vars['eip'] = int(matches.group(1))
            return
        matches = re.match(r'aei|aeim|aeip', cmd)
        if matches:
            return
        matches = re.match(r'aer ([a-z]+)=(\d+)', cmd)
        if matches:
            self.emu.vars[matches.group(1)] = int(matches.group(2))
            return
        matches = re.match(r'ae (\d+),(\d+),=\[(\d+)\]', cmd)
        if matches:
            self.emu.mem.values[(int(matches.group(2)), int(matches.group(3)))] = int(matches.group(1))
            return
        matches = re.match(r'aes', cmd)
        if matches:
            instr = self.instrs[int(self.emu.vars['eip']) - self.base_addr]
            self.emu.vars['eip'] += 1  # update eip first as esil assumes its updated
            self.emu.step(instr)
            return
        matches = re.match(r'e ', cmd)
        if matches:
            return
        raise ValueError('cmd', cmd)

    def cmdj(self, cmd):
        matches = re.match(r'pdj 1 @ (\d+)', cmd)
        if matches:
            return [{'esil': self.instrs[int(matches.group(1)) - self.base_addr], 'size': 1}]
        matches = re.match(r'aerj', cmd)
        if matches:
            return {name: val for name, val in self.emu.vars.items() if not name.startswith('$')}
        raise ValueError('cmd', cmd)
