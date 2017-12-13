from expects.matchers import Matcher

from analysis.block import Block
from analysis.func import Function

__all__ = ['to_blocks', 'to_func', 'eq_func']


def to_blocks(block_defs):
    blocks = [Block(block_def.get('addr_sizes', set()), block_def.get('instrs', [])) for block_def in block_defs]
    for block, block_def in zip(blocks, block_defs):
        block.condition = block_def.get('condition', None)
        block.children = tuple(blocks[i] for i in block_def.get('children', ()))
    return blocks


def to_func(addr, block_defs):
    blocks = to_blocks(block_defs)
    func = Function(addr, blocks[0])
    for i, (block, block_dfs) in enumerate(zip(blocks, func.blocks)):
        if block is not block_dfs:
            raise ValueError(f'block {i} is not sorted via dfs (needed so eq_func errors make sense)')
    return func


class eq_func(Matcher):
    def __init__(self, expected):
        self._expected = expected

    @staticmethod
    def _check_eq(msg, value, expected):
        if value != expected:
            raise ValueError(msg, str(value), str(expected))

    def _match(self, func):
        try:
            self._check_eq('addr is different', func.addr, self._expected.addr)
            func_blocks, expected_blocks = list(func.blocks), list(self._expected.blocks)
            self._check_eq('# of blocks are different', len(func_blocks), len(expected_blocks))
            for i, (func_block, expected_block) in enumerate(zip(func_blocks, expected_blocks)):
                self._check_eq(f'block {i} instrs are different', func_block.instrs, expected_block.instrs)
                self._check_eq(f'block {i} addr_sizes are different', func_block.addr_sizes, expected_block.addr_sizes)
                self._check_eq(
                    f'block {i} condition is different', func_block.condition, expected_block.condition
                )
                func_children = tuple(func_blocks.index(block) for block in func_block.children)
                expected_children = tuple(expected_blocks.index(block) for block in expected_block.children)
                self._check_eq(f'block {i} children are different', func_children, expected_children)
            return True, []
        except ValueError as e:
            return False, e.args
