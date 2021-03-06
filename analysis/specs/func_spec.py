from contextlib import ExitStack
from unittest.mock import patch

from expects import *

from analysis.func import ESILToFunc, func_merge_single_children, func_remove_same_children, func_simplify
from analysis.specs._stub import *
from analysis.specs._utils import eq_func, to_func

with description('ESILToFunc'):
    with description('sa_include_flag_deps'):
        with it('converts flags'):
            expect(ESILToFunc._sa_include_flag_deps([
                ('eax', '[4]=', '+', 'eax', 'ebx'),
                ('of', '=', '$o'),
                ('sf', '=', '$s'),
                ('zf', '=', '$z'),
                ('cf', '=', '$c31'),
                ('pf', '=', '$p'),
            ])).to(equal([
                ('tmp', '=', '+', 'eax', 'ebx'),
                ('eax', '[4]=', 'tmp'),
                ('of', '=', '$o', 'tmp'),
                ('sf', '=', '$s', 'tmp'),
                ('zf', '=', '$z', 'tmp'),
                ('cf', '=', '$c31', 'tmp'),
                ('pf', '=', '$p', 'tmp'),
            ]))

        with it('does not modify non-flag instructions'):
            expect(ESILToFunc._sa_include_flag_deps([
                ('eax', '=', 'eax', 'ebx'),
            ])).to(equal([
                ('eax', '=', 'eax', 'ebx'),
            ]))

    with description('sa_include_subword_deps'):
        with it('updates on subword writes'):
            expect(ESILToFunc._sa_include_subword_deps([
                ('al', '=', '1'),
            ])).to(equal([
                ('al', '=', '1'),
                ('eax', 'l=', 'al'),
            ]))

        with it('updates on subword accesses'):
            expect(ESILToFunc._sa_include_subword_deps([
                ('ebx', '[2]=', 'al'),
            ])).to(equal([
                ('al', '=l', 'eax'),
                ('ebx', '[2]=', 'al'),
            ]))

    with description('convert'):
        with it('converts constants'):
            expect(ESILToFunc(
                '1,eax,=,'
                '0x1,eax,=,'
                '$0,$z,=,'
                '$1,$z,=', 0, 4
            ).convert()).to(eq_func(to_func(0, [{'addr_sizes': {(0, 4)}, 'instrs': [
                ('eax', '=', 1),
                ('eax', '=', 1),
                ('$z', '=', 0),
                ('$z', '=', 1),
            ]}])))

        with it('converts unary operations'):
            expect(ESILToFunc(
                'zf,!,zf,=', 0, 4
            ).convert()).to(eq_func(to_func(0, [{'addr_sizes': {(0, 4)}, 'instrs': [
                ('tmp_0', '=', '!', 'zf'),
                ('zf', '=', 'tmp_0'),
            ]}])))

        with it('converts ++= to + (no point having separate operation)'):
            expect(ESILToFunc(
                'eax,++=', 0, 4
            ).convert()).to(eq_func(to_func(0, [{'addr_sizes': {(0, 4)}, 'instrs': [
                ('eax', '=', '+', 'eax', 1),
            ]}])))

        with it('converts --= to - (no point having separate operation)'):
            expect(ESILToFunc(
                'eax,--=', 0, 4
            ).convert()).to(eq_func(to_func(0, [{'addr_sizes': {(0, 4)}, 'instrs': [
                ('eax', '=', '-', 'eax', 1),
            ]}])))

        with it('converts =='):
            expect(ESILToFunc(
                'ebx,eax,==', 0, 4
            ).convert()).to(eq_func(to_func(0, [{'addr_sizes': {(0, 4)}, 'instrs': [
                ('tmp_0', '=', '==', 'eax', 'ebx'),
            ]}])))

        with it('converts binary assigns'):
            expect(ESILToFunc(
                '1,eax,+=', 0, 4
            ).convert()).to(eq_func(to_func(0, [{'addr_sizes': {(0, 4)}, 'instrs': [
                ('eax', '=', '+', 'eax', 1),
            ]}])))

        with it('converts binary operations'):
            expect(ESILToFunc(
                'ebx,eax,+,ecx,=', 0, 4
            ).convert()).to(eq_func(to_func(0, [{'addr_sizes': {(0, 4)}, 'instrs': [
                ('tmp_0', '=', '+', 'eax', 'ebx'),
                ('ecx', '=', 'tmp_0'),
            ]}])))

        with it('converts multiple stacked operations'):
            expect(ESILToFunc(
                '$z,!,ebx,eax,+,*,ecx,=', 0, 4
            ).convert()).to(eq_func(to_func(0, [{'addr_sizes': {(0, 4)}, 'instrs': [
                ('tmp_0', '=', '!', '$z'),
                ('tmp_1', '=', '+', 'eax', 'ebx'),
                ('tmp_2', '=', '*', 'tmp_1', 'tmp_0'),
                ('ecx', '=', 'tmp_2'),
            ]}])))

        with it('converts memory reads'):
            expect(ESILToFunc(
                'eax,[],ebx,=,'
                'eax,[1],ebx,=,'
                'eax,[2],ebx,=,'
                'eax,[4],ebx,=', 0, 4
            ).convert()).to(eq_func(to_func(0, [{'addr_sizes': {(0, 4)}, 'instrs': [
                ('tmp_0', '=[4]', 'eax'), ('ebx', '=', 'tmp_0'),
                ('tmp_1', '=[1]', 'eax'), ('ebx', '=', 'tmp_1'),
                ('tmp_2', '=[2]', 'eax'), ('ebx', '=', 'tmp_2'),
                ('tmp_3', '=[4]', 'eax'), ('ebx', '=', 'tmp_3'),
            ]}])))

        with it('converts memory writes'):
            expect(ESILToFunc(
                '1,eax,=[],'
                '1,eax,=[1],'
                '1,eax,=[2],'
                '1,eax,=[4]', 0, 4
            ).convert()).to(eq_func(to_func(0, [{'addr_sizes': {(0, 4)}, 'instrs': [
                ('eax', '[4]=', 1),
                ('eax', '[1]=', 1),
                ('eax', '[2]=', 1),
                ('eax', '[4]=', 1),
            ]}])))

        with it('raises ValueError if stack is not 0 at the end'):
            expect(lambda: ESILToFunc('1', 0, 4).convert()).to(raise_error(ValueError))

        with it('converts nested branches'):
            expect(ESILToFunc(
                '0,eip,=,zf,?{,1,eip,=,cf,?{,2,eip,=,},3,eip,=,pf,?{,4,eip,=,},5,eip,=,},6,eip,=', 0, 4
            ).convert()).to(eq_func(to_func(0, [
                {'addr_sizes': {(0, 4)}, 'instrs': [('eip', '=', 0)], 'condition': 'zf', 'children': (1, 6)},
                {'addr_sizes': {(0, 4)}, 'instrs': [('eip', '=', 1)], 'condition': 'cf', 'children': (2, 3)},
                {'addr_sizes': {(0, 4)}, 'instrs': [('eip', '=', 2)], 'children': (3,)},
                {'addr_sizes': {(0, 4)}, 'instrs': [('eip', '=', 3)], 'condition': 'pf', 'children': (4, 5)},
                {'addr_sizes': {(0, 4)}, 'instrs': [('eip', '=', 4)], 'children': (5,)},
                {'addr_sizes': {(0, 4)}, 'instrs': [('eip', '=', 5)], 'children': (6,)},
                {'addr_sizes': {(0, 4)}, 'instrs': [('eip', '=', 6)]},
            ])))

        with it('raises ValueError if stack is not 0 before and after jcc'):
            expect(lambda: ESILToFunc('0,zf,?{', 0, 4).convert()).to(raise_error(ValueError))
            expect(lambda: ESILToFunc('zf,?{,0,}', 0, 4).convert()).to(raise_error(ValueError))

        with it('converts skip'):
            expect(ESILToFunc(
                '3,SKIP,'
                '0,eax,=,'
                '1,eax,=', 0, 4
            ).convert()).to(eq_func(to_func(0, [
                {'addr_sizes': {(0, 4)}, 'instrs': [], 'children': (1,)},
                {'addr_sizes': {(0, 4)}, 'instrs': [('eax', '=', 1)]},
            ])))

        with it('converts goto'):
            expect(ESILToFunc(
                '0,eax,=,'
                '1,eax,=,'
                '3,GOTO', 0, 4
            ).convert()).to(eq_func(to_func(0, [
                {'addr_sizes': {(0, 4)}, 'instrs': [('eax', '=', 0)], 'children': (1,)},
                {'addr_sizes': {(0, 4)}, 'instrs': [('eax', '=', 1)], 'children': (1,)},
            ])))

        with it('converts loop'):
            expect(ESILToFunc(
                '0,eax,=,'
                'LOOP', 0, 4
            ).convert()).to(eq_func(to_func(0, [
                {'addr_sizes': {(0, 4)}, 'instrs': [('eax', '=', 0)], 'children': (0,)},
            ])))

        with it('converts break'):
            expect(ESILToFunc(
                'BREAK,'
                '0,eax,=', 0, 4
            ).convert()).to(eq_func(to_func(0, [
                {'addr_sizes': {(0, 4)}, 'instrs': [], 'children': (1,)},
                {'addr_sizes': {(0, 4)}, 'instrs': []},
            ])))

        with it('converts jmp into start of multi-stacked operation'):
            expect(ESILToFunc(
                '2,GOTO,'
                'eax,eax,+,eax,=', 0, 4
            ).convert()).to(eq_func(to_func(0, [
                {'addr_sizes': {(0, 4)}, 'instrs': [], 'children': (1,)},
                {'addr_sizes': {(0, 4)}, 'instrs': [('tmp_0', '=', '+', 'eax', 'eax'), ('eax', '=', 'tmp_0')]},
            ])))

        with it('raises ValueError if stack is not 0 before jmp'):
            expect(lambda: ESILToFunc('0,0,SKIP', 0, 4).convert()).to(raise_error(ValueError))
            expect(lambda: ESILToFunc('0,0,GOTO', 0, 4).convert()).to(raise_error(ValueError))
            expect(lambda: ESILToFunc('0,LOOP', 0, 4).convert()).to(raise_error(ValueError))
            expect(lambda: ESILToFunc('0,BREAK', 0, 4).convert()).to(raise_error(ValueError))

        with it('raises ValueError if stack is not 0 after jmp'):
            expect(lambda: ESILToFunc('3,GOTO,0,eax,=', 0, 4).convert()).to(raise_error(ValueError))

        with it('raises ValueError for unknown opcodes'):
            expect(lambda: ESILToFunc('??', 0, 4).convert()).to(raise_error(ValueError))

with description('func_remove_same_children'):
    with it('replaces identical blocks with one block'):
        func = to_func(0, [
            {'children': (1, 2)},
            {'children': (3,)},
            {'addr_sizes': {(0, 4)}, 'instrs': [('eax', '=', 0)], 'children': (4, 5)},
            {'addr_sizes': {(4, 4)}, 'instrs': [('eax', '=', 0)], 'children': (4, 5)},
            {'instrs': [('eax', '=', 1)]},
            {'instrs': [('eax', '=', 2)]},
        ])
        func_remove_same_children(func)
        expect(func).to(eq_func(to_func(0, [
            {'children': (1, 2)},
            {'children': (2,)},
            {'addr_sizes': {(0, 4), (4, 4)}, 'instrs': [('eax', '=', 0)], 'children': (3, 4)},
            {'instrs': [('eax', '=', 1)]},
            {'instrs': [('eax', '=', 2)]},
        ])))

with description('func_merge_single_children'):
    with it('merges blocks with single children repeatedly'):
        func = to_func(0, [
            {'instrs': [('eax', '=', 0)], 'children': (1,)},
            {'instrs': [('eax', '=', 1)], 'children': (2,)},
            {'instrs': [('eax', '=', 2)]},
        ])
        func_merge_single_children(func)
        expect(func).to(eq_func(to_func(0, [
            {'instrs': [
                ('eax', '=', 0),
                ('eax', '=', 1),
                ('eax', '=', 2),
            ]},
        ])))

    with it('does not merge blocks who share children'):
        func = to_func(0, [
            {'children': (2,)},
            {'children': (2,)},
            {},
        ])
        func_merge_single_children(func)
        expect(func).to(eq_func(to_func(0, [
            {'children': (2,)},
            {'children': (2,)},
            {},
        ])))

    with it('does not merge blocks with calls'):
        func = to_func(0, [
            {'instrs': [('eax', '=', 0)], 'call': ('somelib', 'somemethod'), 'children': (1,)},
            {'instrs': [('eax', '=', 1)]},
        ])
        func_merge_single_children(func)
        expect(func).to(eq_func(to_func(0, [
            {'instrs': [('eax', '=', 0)], 'call': ('somelib', 'somemethod'), 'children': (1,)},
            {'instrs': [('eax', '=', 1)]},
        ])))

with description('func_simplify'):
    with it('calls simplification routines'):
        with ExitStack() as stack:
            func_simps = [stack.enter_context(patch(f'analysis.func.{name}')) for name in [
                'func_remove_same_children', 'func_merge_single_children',
            ]]
            func_simplify(None)
            for func_simp in func_simps:
                expect(func_simp.call_count).to(be(1))
