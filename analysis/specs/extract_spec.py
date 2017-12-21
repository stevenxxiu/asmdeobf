import textwrap

from expects import *

from analysis.constraint import DisjunctConstConstraint
from analysis.extract import extract_funcs
from analysis.specs._stub import *
from analysis.specs._utils import MockRadare, eq_func, to_func

with description('FuncExtract'):
    with before.each:
        self.r = MockRadare([], 100)

    with it('stops analyzing if return address is variable'):
        r = MockRadare(textwrap.dedent('''
            eax,4,esp,-=,esp,=[4]
            esp,[4],eip,=,4,esp,+=
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        expect(
            extract_funcs(r, 100, DisjunctConstConstraint.from_func_init())[100][0]
        ).to(eq_func(to_func(100, [{'addr_sizes': {(i, 1) for i in range(100, 102)}, 'instrs': [
            ('eip', '=', 101), ('esp', '=', '-', 'esp', 4), ('esp', '[4]=', 'eax'),
            ('eip', '=', 102), ('tmp_0', '=[4]', 'esp'), ('eip', '=', 'tmp_0'), ('esp', '=', '+', 'esp', 4),
        ]}])))

    with it('keeps on analyzing if return address is constant'):
        r = MockRadare(textwrap.dedent('''
            102,4,esp,-=,esp,=[4]
            esp,[4],eip,=,4,esp,+=
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        expect(
            extract_funcs(r, 100, DisjunctConstConstraint.from_func_init())[100][0]
        ).to(eq_func(to_func(100, [{'addr_sizes': {(i, 1) for i in range(100, 103)}, 'instrs': [
            ('eip', '=', 101), ('esp', '=', '-', 'esp', 4), ('esp', '[4]=', 102),
            ('eip', '=', 102), ('tmp_0', '=[4]', 'esp'), ('eip', '=', 'tmp_0'), ('esp', '=', '+', 'esp', 4),
            ('eip', '=', 103), ('tmp_0', '=[4]', 'esp'), ('eip', '=', 'tmp_0'), ('esp', '=', '+', 'esp', 4),
        ]}])))

    with description('breaks up existing blocks'):
        with it('breaks up if there is a jmp into it'):
            r = MockRadare(textwrap.dedent('''
                0,eax,=
                1,eax,=
                101,eip,=
                esp,[4],eip,=,4,esp,+=
            ''').strip().split('\n'), 100)
            expect(
                extract_funcs(r, 100, DisjunctConstConstraint.from_func_init())[100][0]
            ).to(eq_func(to_func(100, [{
                'addr_sizes': {(i, 1) for i in range(100, 101)}, 'instrs': [
                    ('eip', '=', 101), ('eax', '=', 0),
                ], 'children': (1,),
            }, {
                'addr_sizes': {(i, 1) for i in range(101, 103)}, 'instrs': [
                    ('eip', '=', 102), ('eax', '=', 1),
                    ('eip', '=', 103), ('eip', '=', 101),
                ], 'children': (1,),
            }])))

        with it('does not stop analyzing after breaking up if constraints are the same'):
            r = MockRadare(textwrap.dedent('''
                0,eax,=
                0,eax,=
                101,eip,=
            ''').strip().split('\n'), 100)
            expect(
                extract_funcs(r, 100, DisjunctConstConstraint.from_func_init())[100][0]
            ).to(eq_func(to_func(100, [{
                'addr_sizes': {(i, 1) for i in range(100, 101)}, 'instrs': [
                    ('eip', '=', 101), ('eax', '=', 0),
                ], 'children': (1,),
            }, {
                'addr_sizes': {(i, 1) for i in range(101, 103)}, 'instrs': [
                    ('eip', '=', 102), ('eax', '=', 0),
                    ('eip', '=', 103), ('eip', '=', 101),
                ], 'children': (1,),
            }])))

    with it('ignores conditional jmps if the constraint is unsatisfiable'):
        r = MockRadare(textwrap.dedent('''
            eax,eax,^=,$z,zf,=
            zf,!,?{,200,eip,=,}
            1,eax,=
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        expect(
            extract_funcs(r, 100, DisjunctConstConstraint.from_func_init())[100][0]
        ).to(eq_func(to_func(100, [{
            'addr_sizes': {(i, 1) for i in range(100, 102)}, 'instrs': [
                ('eip', '=', 101), ('tmp', '=', '^', 'eax', 'eax'), ('eax', '=', 'tmp'), ('zf', '=', '$z', 'tmp'),
                ('eip', '=', 102), ('tmp_0', '=', '!', 'zf'),
            ], 'children': (1,),
        }, {
            'addr_sizes': {(i, 1) for i in range(101, 104)}, 'instrs': [
                ('eip', '=', 103), ('eax', '=', 1),
                ('eip', '=', 104), ('tmp_0', '=[4]', 'esp'), ('eip', '=', 'tmp_0'), ('esp', '=', '+', 'esp', 4),
            ],
        }])))

    with it('breaks-up & re-analyzes existing block if the constraint is no longer the same'):
        r = MockRadare(textwrap.dedent('''
            eax,eax,^=,$z,zf,=
            zf,!,?{,104,eip,=,}
            ebx,eax,+=,$z,zf,=
            101,eip,=
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        expect(
            extract_funcs(r, 100, DisjunctConstConstraint.from_func_init())[100][0]
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

#     with it('adds flag constraints to conditional jmp targets'):
#         r = MockRadare(textwrap.dedent('''
#             zf,?{,102,eip,=,}
#             zf,?{,200,eip,=,}
#             esp,[4],eip,=,4,esp,+=
#         ''').strip().split('\n'), 100)
#         func = FuncsExtract(r).extract_funcs(100, ConstConstraint())[100][0]
#         expect(func.blocks).to(equal({
#             100: Block([
#                 '101,eip,=,zf,?{,102,eip,=,}',
#             ], [102, 101], ('zf', 0)),
#             101: Block([
#                 '102,eip,=,zf,?{,200,eip,=,}',
#             ], [102]),
#             102: Block([
#                 '103,eip,=,esp,[4],eip,=,4,esp,+=',
#             ], []),
#         }))
