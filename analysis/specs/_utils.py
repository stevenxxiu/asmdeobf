from expects.matchers import Matcher

__all__ = ['eq_func']


class eq_func(Matcher):
    def __init__(self, expected):
        self._expected = expected

    @staticmethod
    def _check_eq(msg, value, expected):
        if value != expected:
            raise ValueError(msg, str(value), str(expected))

    def _match(self, func):
        try:
            self._check_eq('addr is different', func.addr, self._expected[0])
            func_blocks, expected_blocks = list(func.blocks), self._expected[1]
            self._check_eq('# of blocks are different', len(func_blocks), len(expected_blocks))
            for i, (func_block, expected_block) in enumerate(zip(func_blocks, expected_blocks)):
                self._check_eq(f'block {i} instrs are different', func_block.instrs, expected_block['instrs'])
                self._check_eq(f'block {i} addr_sizes are different', func_block.addr_sizes, expected_block['addr_sizes'])
                self._check_eq(
                    f'block {i} condition is different', func_block.condition, expected_block.get('condition', None)
                )
                func_children = tuple(func_blocks.index(block) for block in func_block.children)
                self._check_eq(f'block {i} children are different', func_children, expected_block.get('children', ()))
            return True, []
        except ValueError as e:
            return False, e.args
