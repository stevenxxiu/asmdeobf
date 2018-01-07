import textwrap
from unittest.mock import patch

from expects import *

from analysis.block import Block
from analysis.constraint import ConstConstraint as CCon
from analysis.constraint import DisjunctConstConstraint as DCon
from analysis.extract import FuncExtract, extract_funcs
from analysis.specs._stub import *
from analysis.specs._utils import MockRadare, eq_block, eq_func, to_blocks, to_func
from analysis.winapi import win_api

with description('FuncExtract'):
    with description('_explore_block (all tests makes sure explore takes place on instruction boundaries)'):
        with it('keeps and runs instructions already in block'):
            block, propagate_blocks = Block(set(), [
                ('eip', '=', 101), ('eax', '=', 0),
            ]), []
            e = FuncExtract(MockRadare([], 100), None, {}, None, (101,))
            e.block_to_constraint[block] = DCon([CCon({'eip': 100})])
            e._explore_block(block, propagate_blocks)
            expect(block).to(eq_block(Block(set(), [
                ('eip', '=', 101), ('eax', '=', 0),
            ])))
            expect(propagate_blocks).to(equal([(block, 2, DCon([CCon({'eip': 101, 'eax': 0})]))]))

        with it('appends new instructions'):
            block, propagate_blocks = Block(), []
            e = FuncExtract(MockRadare(['0,eax,='], 100), None, {}, None, (101,))
            e.block_to_constraint[block] = DCon([CCon({'eip': 100})])
            e._explore_block(block, propagate_blocks)
            expect(block).to(eq_block(Block({(100, 1)}, [
                ('eip', '=', 101), ('eax', '=', 0),
            ])))
            expect(propagate_blocks).to(equal([(block, 2, DCon([CCon({'eip': 101, 'eax': 0})]))]))

        with it('ends if return address is variable'):
            block, propagate_blocks = Block(set(), [
                ('eip', '=', 'eax'),
            ]), []
            e = FuncExtract(MockRadare([], 100), None, {}, None, ())
            e.block_to_constraint[block] = DCon([CCon({'eip': 100})])
            e._explore_block(block, propagate_blocks)
            expect(propagate_blocks).to(equal([(block, 1, DCon([CCon()]))]))

        with it('ends if there is an api call'):
            block, propagate_blocks = Block(set(), [
                ('tmp_0', '=[4]', 200),
                ('eip', '=', 'tmp_0'),
            ]), []
            e = FuncExtract(MockRadare([], 100), None, {}, None, ())
            e.block_to_constraint[block] = DCon([CCon({'eip': 100})])
            e._explore_block(block, propagate_blocks)
            expect(block.instrs).to(equal([]))
            expect(block.call).to(equal(('somelib', 'somemethod')))
            expect(block.children[0]).to(eq_block(Block()))
            expect(propagate_blocks).to(equal([(block, 0, DCon([CCon()]))]))

        with context('address already found'):
            with before.each:
                self.e = FuncExtract(MockRadare([], 100), None, {}, None, ())
                self.goto_block = Block({(100, 1), (101, 1)}, [
                    ('eip', '=', 101), ('eax', '=', 0),
                    ('eip', '=', 102), ('eax', '=', 1),
                ])
                self.e.addr_to_block[100] = (self.goto_block, 0)
                self.e.addr_to_block[101] = (self.goto_block, 2)
                self.e.block_to_constraint[self.goto_block] = self.goto_con = DCon()

            with context('in middle of block'):
                with it('ends and splits up block'):
                    block = Block()
                    self.e.block_to_constraint[block] = DCon([CCon({'eip': 101})])
                    self.e._explore_block(block, [])
                    upper_half = self.e.addr_to_block[100][0]
                    lower_half = self.e.addr_to_block[101][0]
                    expect(upper_half.instrs).to(equal([('eip', '=', 101), ('eax', '=', 0)]))
                    expect(lower_half.instrs).to(equal([('eip', '=', 102), ('eax', '=', 1)]))
                    expect(upper_half.children).to(equal((lower_half,)))
                    expect(block.children).to(equal((lower_half,)))
                    expect(self.e.visited).to(equal({lower_half}))

                with it('ends and splits up block if block is same as go to block'):
                    self.e.r = MockRadare(['101,eip,='], 102)
                    self.e.block_to_constraint[self.goto_block] = DCon([CCon({'eip': 102})])
                    self.e._explore_block(self.goto_block, [])
                    upper_half = self.e.addr_to_block[100][0]
                    lower_half = self.e.addr_to_block[101][0]
                    expect(upper_half.instrs).to(equal([('eip', '=', 101), ('eax', '=', 0)]))
                    expect(lower_half.instrs).to(equal([
                        ('eip', '=', 102), ('eax', '=', 1),
                        ('eip', '=', 103), ('eip', '=', 101)
                    ]))
                    expect(upper_half.children).to(equal((lower_half,)))
                    expect(self.goto_block.children).to(equal((lower_half,)))
                    expect(self.e.visited).to(equal({lower_half}))

                with it('updates entries in propagate_blocks if it contains goto_block constraints'):
                    block, propagate_blocks = Block(), [
                        (self.goto_block, 1, DCon()),
                        (self.goto_block, 2, DCon())
                    ]
                    self.e.block_to_constraint[block] = DCon([CCon({'eip': 101})])
                    self.e._explore_block(block, propagate_blocks)
                    lower_half = self.e.addr_to_block[101][0]
                    expect(propagate_blocks).to(contain(
                        (self.goto_block, 1, DCon()),
                        (lower_half, 0, DCon()),
                    ))

                with it('adds goto block and block constraints to propagate_blocks'):
                    block, propagate_blocks = Block(), []
                    self.e.block_to_constraint[block] = DCon([CCon({'eip': 101})])
                    self.e._explore_block(block, propagate_blocks)
                    lower_half = self.e.addr_to_block[101][0]
                    expect(self.e.block_to_constraint[self.goto_block]).to(equal(DCon()))
                    expect(propagate_blocks).to(equal([
                        (self.goto_block, 0, DCon()),
                        (lower_half, 0, DCon([CCon({'eip': 101})])),
                    ]))

            with context('at the start of a block'):
                with it('ends'):
                    block = Block()
                    self.e.block_to_constraint[block] = DCon([CCon({'eip': 100})])
                    self.e._explore_block(block, [])
                    expect(block.children).to(equal((self.goto_block,)))

                with it('adds block constraints to propagate_blocks'):
                    block, propagate_blocks = Block(), []
                    self.e.block_to_constraint[block] = DCon([CCon({'eip': 100})])
                    self.e._explore_block(block, propagate_blocks)
                    expect(propagate_blocks).to(equal([(self.goto_block, 0, DCon([CCon({'eip': 100})]))]))

    with description('_propagate_constraints'):
        with before.each:
            self.e = FuncExtract(MockRadare([], 100), None, {}, None, ())

        with it('adds and finalizes constraint'):
            block = Block()
            self.e._propagate_constraints([
                (block, 0, DCon([CCon({'eax': 1, 'tmp_0': 1})]))
            ])
            expect(self.e.block_to_constraint).to(equal({
                block: DCon([CCon({'eax': 1})])
            }))

        with it('widens and finalizes existing constraint'):
            block = Block()
            self.e.block_to_constraint[block] = DCon([CCon({'eax': 1, 'ebx': 1})])
            self.e._propagate_constraints([
                (block, 0, DCon([CCon({'eax': 1, 'ebx': 2, 'tmp_0': 1})]))
            ])
            expect(self.e.block_to_constraint).to(equal({
                block: DCon([CCon({'eax': 1})])
            }))

        with it('propagates to children when starting half-way in block'):
            blocks = to_blocks([{'instrs': [('eax', '=', 1), ('eax', '=', 2)], 'children': (1,)}, {}])
            self.e.visited = {blocks[0]}
            self.e._propagate_constraints([
                (blocks[0], 1, DCon([CCon({'eax': 0})]))
            ])
            expect(self.e.block_to_constraint).to(equal({
                blocks[1]: DCon([CCon({'eax': 2})]),
            }))

        with it('propagates to children when there is an api call'):
            blocks = to_blocks([{'call': ('somelib', 'somemethod'), 'children': (1,)}, {}])
            self.e.visited = {blocks[0]}
            with patch.object(win_api, 'get_stack_change', return_value=0):
                self.e._propagate_constraints([
                    (blocks[0], 0, DCon([CCon({'esp': ('esp_0', 0)}, stack_values={(-4, 4): 1})]))
                ])
            expect(self.e.block_to_constraint).to(equal({
                blocks[0]: DCon([CCon({'esp': ('esp_0', 0)}, stack_values={(-4, 4): 1})]),
                blocks[1]: DCon([CCon({'eip': 1, 'esp': ('esp_0', 4)})]),
            }))

        with it('propagates to children when there is a satisfiable condition'):
            blocks = to_blocks([{'condition': 'zf', 'children': (1, 2)}, {}, {}])
            self.e.visited = {blocks[0]}
            self.e._propagate_constraints([
                (blocks[0], 0, DCon([CCon({'zf': 1})]))
            ])
            expect(self.e.block_to_constraint).to(equal({
                blocks[0]: DCon([CCon({'zf': 1})]),
                blocks[1]: DCon([CCon({'zf': 1})]),
            }))

        with it('prepares to explore propagated blocks that are not visited before'):
            blocks = to_blocks([{'children': (1, 2)}, {}, {}])
            self.e.visited = {blocks[0], blocks[1]}
            expect(self.e._propagate_constraints([
                (blocks[0], 0, DCon([CCon()]))
            ])).to(equal({blocks[2]}))

        with it('updates end_constraint whenever a block with no children is visited'):
            blocks = to_blocks([{'children': (1, 2)}, {'instrs': [('ebx', '=', 2)]}, {}])
            self.e.end_constraint = DCon([CCon({'eax': 1, 'ebx': 1})])
            self.e.visited = {blocks[0], blocks[1]}
            self.e._propagate_constraints([
                (blocks[0], 0, DCon([CCon({'eax': 1})]))
            ])
            expect(self.e.end_constraint).to(equal(DCon([CCon({'eax': 1})])))

    with description('extract'):
        with it('breaks-up & re-analyzes existing block if the constraint is no longer the same'):
            r = MockRadare(textwrap.dedent('''
                eax,eax,^=,$z,zf,=
                zf,!,?{,104,eip,=,}
                ebx,eax,+=,$z,zf,=
                101,eip,=
                esp,[4],eip,=,4,esp,+=
            ''').strip().split('\n'), 100)
            expect(
                extract_funcs(r, 100, DCon.from_func_init())[100][0]
            ).to(eq_func(to_func(100, [{
                'addr_sizes': {(i, 1) for i in range(100, 101)}, 'instrs': [
                    ('eip', '=', 101), ('tmp', '=', '^', 'eax', 'eax'), ('eax', '=', 'tmp'), ('zf', '=', '$z', 'tmp'),
                ], 'children': (1,),
            }, {
                'addr_sizes': {(i, 1) for i in range(101, 102)}, 'instrs': [
                    ('eip', '=', 102), ('tmp_0', '=', '!', 'zf'),
                ], 'condition': 'tmp_0', 'children': (2, 3),
            }, {
                'addr_sizes': {(101, 1), (104, 1)}, 'instrs': [
                    ('eip', '=', 104),
                    ('eip', '=', 105), ('tmp_0', '=[4]', 'esp'), ('eip', '=', 'tmp_0'), ('esp', '=', '+', 'esp', 4),
                ],
            }, {
                'addr_sizes': {(i, 1) for i in range(101, 104)}, 'instrs': [
                    ('eip', '=', 103), ('tmp', '=', '+', 'eax', 'ebx'), ('eax', '=', 'tmp'), ('zf', '=', '$z', 'tmp'),
                    ('eip', '=', 104), ('eip', '=', 101),
                ], 'children': (1,),
            }])))

        with it('updates branch constraints on conditional jmp'):
            r = MockRadare(textwrap.dedent('''
                zf,?{,102,eip,=,}
                zf,?{,200,eip,=,}
                esp,[4],eip,=,4,esp,+=
            ''').strip().split('\n'), 100)
            expect(
                extract_funcs(r, 100, DCon.from_func_init())[100][0]
            ).to(eq_func(to_func(100, [{
                'addr_sizes': {(i, 1) for i in range(100, 101)}, 'instrs': [
                    ('eip', '=', 101),
                ], 'condition': 'zf', 'children': (1, 3),
            }, {
                'addr_sizes': {(i, 1) for i in range(100, 101)}, 'instrs': [
                    ('eip', '=', 102),
                ], 'children': (2,),
            }, {
                'addr_sizes': {(i, 1) for i in range(102, 103)}, 'instrs': [
                    ('eip', '=', 103), ('tmp_0', '=[4]', 'esp'), ('eip', '=', 'tmp_0'), ('esp', '=', '+', 'esp', 4),
                ],
            }, {
                'addr_sizes': {(i, 1) for i in range(100, 102)}, 'instrs': [
                    ('eip', '=', 102),
                ], 'children': (4,),
            }, {
                'addr_sizes': {(i, 1) for i in range(101, 102)}, 'instrs': [], 'children': (2,),
            }])))
