from contextlib import ExitStack
from textwrap import dedent
from unittest.mock import patch

from expects import *

from analysis.block import (
    Block, block_simplify, sa_common_subexpr, sa_const_fold, sa_copy_propagate, sa_dead_code_elim, sa_expr_simp,
    sa_mem_elim, sa_sub_assign_retrieve, sa_to_ssa, ssa_to_sa
)
from analysis.specs._stub import *
from analysis.specs._utils import to_blocks

with description('Block'):
    with description('__str__'):
        with it('converts to str'):
            expect(str(Block(instrs=[
                ('eax', '=', 1),
                ('eax', '=', '!', 1),
                ('eax', '=', '+', 'ebx', 1),
            ]))).to(equal(dedent('''
                eax = 0x1
                eax = ! 0x1
                eax = ebx + 0x1
            ''').strip()))

        with it('raises ValueError on unknown op arity'):
            expect(lambda: str(Block(instrs=[
                ('eax', '=', '??', 1, 1, 1),
            ]))).to(raise_error(ValueError))

    with description('split'):
        with it('splits block'):
            blocks = to_blocks([
                {'children': (2,)},
                {'children': (2,)},
                {'addr_sizes': {(0, 4)}, 'instrs': [
                    ('eax', '=', 1), ('eax', '=', 2)
                ], 'condition': 'tmp', 'children': (3, 4)},
                {'children': ()},
                {'children': ()},
            ])
            upper_half, lower_half = blocks[2], blocks[2].split(1)
            expect(blocks[0].children).to(equal((upper_half,)))
            expect(blocks[1].children).to(equal((upper_half,)))
            expect(upper_half.addr_sizes).to(equal({(0, 4)}))
            expect(upper_half.instrs).to(equal([('eax', '=', 1)]))
            expect(upper_half.parents).to(equal({blocks[0], blocks[1]}))
            expect(upper_half.children).to(equal(()))
            expect(lower_half.addr_sizes).to(equal({(0, 4)}))
            expect(lower_half.instrs).to(equal([('eax', '=', 2)]))
            expect(lower_half.parents).to(equal(set()))
            expect(lower_half.condition).to(equal('tmp'))
            expect(lower_half.children).to(equal((blocks[3], blocks[4])))

        with it('splits addr_sizes'):
            blocks = to_blocks([{'addr_sizes': {(0, 4), (4, 4)}, 'instrs': []}])
            upper_half, lower_half = blocks[0], blocks[0].split(0, 4)
            expect(upper_half.addr_sizes).to(equal({(0, 4)}))
            expect(lower_half.addr_sizes).to(equal({(4, 4)}))

    with it('merges blocks no matter how many children the block has'):
        blocks = to_blocks([
            {'children': (2,)},
            {'children': (2,)},
            {'addr_sizes': {(0, 4)}, 'instrs': [('eax', '=', 1)], 'condition': 'tmp_1', 'children': (3, 4)},
            {'addr_sizes': {(4, 4)}, 'instrs': [('eax', '=', 2)], 'condition': 'tmp_2', 'children': (5, 6)},
            {'children': ()},
            {'children': ()},
            {'children': ()},
        ])
        upper_half, lower_half = blocks[2], blocks[3]
        upper_half.merge(lower_half)
        expect(blocks[0].children).to(equal((upper_half,)))
        expect(blocks[1].children).to(equal((upper_half,)))
        expect(upper_half.addr_sizes).to(equal({(0, 4), (4, 4)}))
        expect(upper_half.instrs).to(equal([('eax', '=', 1), ('eax', '=', 2)]))
        expect(upper_half.condition).to(equal('tmp_2'))
        expect(upper_half.parents).to(equal({blocks[0], blocks[1]}))
        expect(upper_half.children).to(equal((blocks[5], blocks[6])))
        expect(lower_half.parents).to(equal(set()))
        expect(lower_half.children).to(equal(()))
        expect(blocks[4].parents).to(equal(set()))

    with description('children.setter'):
        with it('only allows setting with tuples'):
            expect(lambda: setattr(Block(), 'children', [Block(), Block()])).to(raise_error(ValueError))

        with it('updates children & parents after setting children'):
            blocks = [Block(), Block(), Block(), Block(), Block()]
            blocks[0].children = (blocks[1], blocks[2])
            expect(blocks[0].children).to(equal((blocks[1], blocks[2])))
            expect(blocks[1].parents).to(equal({blocks[0]}))
            expect(blocks[2].parents).to(equal({blocks[0]}))
            blocks[0].children = (blocks[3], blocks[4])
            expect(blocks[0].children).to(equal((blocks[3], blocks[4])))
            expect(blocks[1].parents).to(equal(set()))
            expect(blocks[2].parents).to(equal(set()))
            expect(blocks[3].parents).to(equal({blocks[0]}))
            expect(blocks[4].parents).to(equal({blocks[0]}))


with description('sa_to_ssa'):
    with it('changes to ssa form'):
        expect(sa_to_ssa([
            ('eax', '=', '+', 'eax', 'ecx'),
            ('ebx', '=', 'eax'),
            ('eax', '=', 'ebx'),
        ])).to(equal(([
            ('eax_1', '=', '+', 'eax_0', 'ecx_0'),
            ('ebx_1', '=', 'eax_1'),
            ('eax_2', '=', 'ebx_1'),
        ], {'eax': 'eax_2', 'ebx': 'ebx_1', 'ecx': 'ecx_0'})))

    with it('works with subwords'):
        expect(sa_to_ssa([
            ('al', 'x=', 'eax'),
        ])).to(equal(([
            ('al_1', 'x=', 'eax_0'),
        ], {'al': 'al_1', 'eax': 'eax_0'})))

    with it('recounts all names'):
        expect(sa_to_ssa([
            ('tmp_3', '=', 'tmp_2'),
            ('tmp', '=', 'tmp_3'),
        ])).to(equal(([
            ('tmp_1', '=', 'tmp_0'),
            ('tmp_2', '=', 'tmp_1'),
        ], {'tmp': 'tmp_2', 'tmp_2': 'tmp_0', 'tmp_3': 'tmp_1'})))

with description('ssa_to_sa'):
    with it('recounts & remove counters from initial & final registers'):
        expect(ssa_to_sa([
            ('eax_2', '=', '+', 'eax_1', 'ecx_1'),
            ('ebx_1', '[]=', 'eax_2'),
            ('ebx_2', '=', 'eax_2'),
            ('eax_3', '=', 'ebx_2'),
        ])).to(equal(([
            ('eax_1', '=', '+', 'eax', 'ecx'),
            ('ebx', '[]=', 'eax_1'),
            ('ebx', '=', 'eax_1'),
            ('eax', '=', 'ebx'),
        ], {'eax_1': 'eax', 'eax_2': 'eax_1', 'eax_3': 'eax', 'ebx_1': 'ebx', 'ebx_2': 'ebx', 'ecx_1': 'ecx'})))

with description('sa_expr_simp'):
    with it('simplifies xor same register to 0'):
        expect(sa_expr_simp([
            ('r2', '=', '^', 'r1', 'r1'),
        ])).to(equal([
            ('r2', '=', 0),
        ]))

    with it('simplifies xor expressions'):
        expect(sa_expr_simp([
            ('r3', '=', '^', 'r1', 'r2'),
            ('r4', '=', '^', 'r3', 'r1'),
        ])).to(equal([
            ('r3', '=', '^', 'r1', 'r2'),
            ('r4', '=', 'r2'),
        ]))

    with it('simplifies additions'):
        expect(sa_expr_simp([
            ('r2', '=', '+', 'r1', 1),
            ('r3', '=', '+', 'r2', 1),
            ('r4', '=', '-', 'r3', 3),
            ('r5', '=', '+', 'r4', 1),
        ])).to(equal([
            ('r2', '=', '+', 'r1', 1),
            ('r3', '=', '+', 'r1', 2),
            ('r4', '=', '-', 'r1', 1),
            ('r5', '=', 'r1'),
        ]))

with description('sa_mem_elim'):
    with description('read'):
        with it('simplifies for constant addresses'):
            expect(sa_mem_elim([
                (0, '[4]=', 1),
                (4, '[4]=', 2),
                ('r1', '=[4]', 0),
                ('r2', '=[4]', 4),
            ])).to(equal([
                (0, '[4]=', 1),
                (4, '[4]=', 2),
                ('r1', '=', 1),
                ('r2', '=', 2),
            ]))

        with it('simplifies for register + constant'):
            expect(sa_mem_elim([
                ('s2', '=', '+', 's1', 4),
                ('s3', '=', '-', 's1', 4),
                ('s1', '[4]=', 1),
                ('s2', '[4]=', 2),
                ('s3', '[4]=', 3),
                ('r1', '=[4]', 's1'),
                ('r2', '=[4]', 's2'),
                ('r3', '=[4]', 's3'),
            ])).to(equal([
                ('s2', '=', '+', 's1', 4),
                ('s3', '=', '-', 's1', 4),
                ('s1', '[4]=', 1),
                ('s2', '[4]=', 2),
                ('s3', '[4]=', 3),
                ('r1', '=', 1),
                ('r2', '=', 2),
                ('r3', '=', 3),
            ]))

        with it('simplifies re-reads even for overlaps'):
            expect(sa_mem_elim([
                ('r1', '=[4]', 0),
                ('r2', '=[4]', 2),
                ('r3', '=[4]', 0),
                ('r4', '=[4]', 2),
            ])).to(equal([
                ('r1', '=[4]', 0),
                ('r2', '=[4]', 2),
                ('r3', '=', 'r1'),
                ('r4', '=', 'r2'),
            ]))

        with it('simplifies re-reads after write (regression)'):
            expect(sa_mem_elim([
                ('s1', '[4]=', 0),
                ('r1', '=[4]', 0),
                ('r2', '=[4]', 0),
            ])).to(equal([
                ('s1', '[4]=', 0),
                ('r1', '=[4]', 0),
                ('r2', '=', 'r1'),
            ]))

        with it('does not simplify for write in-between with overlap'):
            expect(sa_mem_elim([
                (0, '[4]=', 1),
                (2, '[4]=', 2),
                ('r1', '=[4]', 0),
            ])).to(equal([
                (0, '[4]=', 1),
                (2, '[4]=', 2),
                ('r1', '=[4]', 0),
            ]))

        with it('does not simplify for write in-between with unknown register'):
            expect(sa_mem_elim([
                (0, '[4]=', 1),
                ('s1', '[4]=', 2),
                ('r1', '=[4]', 0),
            ])).to(equal([
                (0, '[4]=', 1),
                ('s1', '[4]=', 2),
                ('r1', '=[4]', 0),
            ]))

    with description('write'):
        with it('removes redundant write even if unrelated value is read in-between'):
            # redundant write if unrelated value is read in-between
            expect(sa_mem_elim([
                (0, '[4]=', 1),
                ('r1', '=[4]', 4),
                (0, '[4]=', 2),
            ])).to(equal([
                ('r1', '=[4]', 4),
                (0, '[4]=', 2),
            ]))

        with it('preserves write if overlapped value is read in-between'):
            expect(sa_mem_elim([
                (0, '[4]=', 1),
                ('r1', '=[4]', 2),
                (0, '[4]=', 2),
            ])).to(equal([
                (0, '[4]=', 1),
                ('r1', '=[4]', 2),
                (0, '[4]=', 2),
            ]))

        with it('preserves write if unknown memory is read in-between'):
            expect((sa_mem_elim([
                (0, '[4]=', 1),
                ('r1', '=[4]', 's1'),
                (0, '[4]=', 2),
            ]))).to(equal([
                (0, '[4]=', 1),
                ('r1', '=[4]', 's1'),
                (0, '[4]=', 2),
            ]))

with description('sa_common_subexpr'):
    with it('substitutes common expressions'):
        expect(sa_common_subexpr([
            ('r2', '=', '*', 'r0', 'r1'),
            ('r3', '=', '*', 'r0', 'r1'),
        ])).to(equal([
            ('r2', '=', '*', 'r0', 'r1'),
            ('r3', '=', 'r2'),
        ]))

with description('sa_copy_propagate'):
    with it('substitutes expressions with their equivalents'):
        expect(sa_copy_propagate([
            ('r1', '=', 'r0'),
            ('r3', '=', '*', 'r1', 'r2'),
        ])).to(equal([
            ('r1', '=', 'r0'),
            ('r3', '=', '*', 'r0', 'r2'),
        ]))

    with it('substitutes memory write vars with their equivalents'):
        expect(sa_copy_propagate([
            ('r1', '=', 'r0'),
            ('r1', '[4]=', '*', 'r2', 'r3'),
        ])).to(equal([
            ('r1', '=', 'r0'),
            ('r0', '[4]=', '*', 'r2', 'r3'),
        ]))

with description('sa_sub_assign_retrieve'):
    with it('replaces sub assign then retrieve with an assign equivalent'):
        expect(sa_sub_assign_retrieve([
            ('r1', 'l=', 'r0'),
            ('r2', '=l', 'r1'),
            ('r4', 'h=', 'r3'),
            ('r5', '=h', 'r4'),
            ('r7', 'x=', 'r6'),
            ('r8', '=x', 'r7'),
        ])).to(equal([
            ('r1', 'l=', 'r0'),
            ('r2', '=', 'r0'),
            ('r4', 'h=', 'r3'),
            ('r5', '=', 'r3'),
            ('r7', 'x=', 'r6'),
            ('r8', '=', 'r6'),
        ]))

with description('sa_const_fold'):
    with it('folds + and -'):
        expect(sa_const_fold([
            ('r0', '=', '+', 1, 2),
            ('r1', '=', '-', 3, 1),
        ])).to(equal([
            ('r0', '=', 3),
            ('r1', '=', 2),
        ]))

with description('sa_dead_code_elim'):
    with it('preserves writes to useful vars and any ancestor vars which taint useful vars'):
        expect(sa_dead_code_elim([
            ('r_0', '=', 1),
            ('r_1', '=', 'r_0'),
            ('s_0', '=', 'r_1'),
            ('t_0', '=', 'r_1'),
        ], ['s_0'])).to(equal([
            ('r_0', '=', 1),
            ('r_1', '=', 'r_0'),
            ('s_0', '=', 'r_1'),
        ]))

    with it('preserves writes to memory and any ancestor vars which taint any var in the expression'):
        expect(sa_dead_code_elim([
            ('r_0', '=', 1),
            ('r_1', '=', 2),
            ('r_2', '=', 3),
            ('r_2', '[4]=', '+', 'r_0', 'r_1'),
            ('t_0', '=', 'r_1'),
        ], [])).to(equal([
            ('r_0', '=', 1),
            ('r_1', '=', 2),
            ('r_2', '=', 3),
            ('r_2', '[4]=', '+', 'r_0', 'r_1'),
        ]))

with description('block_simplify'):
    with it('converts to and from ssa form'):
        with patch('analysis.block.sa_to_ssa', side_effect=[([], {})]) as sa_to_ssa_, \
                patch('analysis.block.ssa_to_sa', side_effect=[([], {})]) as ssa_to_sa_:
            block_simplify(Block())
            expect(sa_to_ssa_.call_count).to(equal(1))
            expect(ssa_to_sa_.call_count).to(equal(1))

    with it('repeatedly calls simplification routines until the lengths of instructions stay constant'):
        with ExitStack() as stack:
            sa_simps = [stack.enter_context(patch(f'analysis.block.{name}', side_effect=(
                (lambda instrs: instrs) if name != 'sa_dead_code_elim' else
                (lambda instrs, _: instrs[:-1] if len(instrs) > 2 else instrs[::-1])
            ))) for name in [
                'sa_expr_simp', 'sa_common_subexpr', 'sa_sub_assign_retrieve', 'sa_copy_propagate', 'sa_const_fold',
                'sa_mem_elim', 'sa_dead_code_elim',
            ]]
            block = Block(instrs=[
                ('eax', '=', 0),
                ('eax', '=', 1),
                ('eax', '=', 2),
                ('eax', '=', 3),
            ])
            block_simplify(block)
            for sa_simp in sa_simps:
                expect(sa_simp.call_count).to(equal(3))
            expect(len(block.instrs)).to(equal(2))

    with it('maps block condition'):
        block = Block(instrs=[('tmp_2', '=', 0), ('tmp_3', '=', 1)])
        block.condition = 'tmp_3'
        block_simplify(block)
        expect(block.condition).to(equal('tmp_1'))
