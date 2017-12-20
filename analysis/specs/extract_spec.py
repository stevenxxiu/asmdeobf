import re
import textwrap

from expects import *

from analysis.block import Block
from analysis.constraint import ConstConstraint, DisjunctConstConstraint
from analysis.extract import FuncExtract
from analysis.specs._stub import *
from analysis.specs._utils import MockRadare

with description('FuncExtract'):
    with before.each:
        self.r = MockRadare([], 100)
        self.func_extract = FuncExtract(self.r, 100, {}, DisjunctConstConstraint(), ())

#     with it('stops analyzing if return address is variable'):
#         r = MockRadare(textwrap.dedent('''
#             eax,4,esp,-=,esp,=[4]
#             esp,[4],eip,=,4,esp,+=
#             esp,[4],eip,=,4,esp,+=
#         ''').strip().split('\n'), 100)
#         func = FuncsExtract(r).extract_funcs(100, ConstConstraint())[100][0]
#         expect(func.blocks).to(equal({
#             100: Block([
#                 '101,eip,=,eax,4,esp,-=,esp,=[4]',
#                 '102,eip,=,esp,[4],eip,=,4,esp,+=',
#             ], []),
#         }))
#
#     with it('keeps on analyzing if return address is constant'):
#         r = MockRadare(textwrap.dedent('''
#             102,4,esp,-=,esp,=[4]
#             esp,[4],eip,=,4,esp,+=
#             esp,[4],eip,=,4,esp,+=
#         ''').strip().split('\n'), 100)
#         func = FuncsExtract(r).extract_funcs(100, ConstConstraint())[100][0]
#         expect(func.blocks).to(equal({
#             100: Block([
#                 '101,eip,=,102,4,esp,-=,esp,=[4]',
#                 '102,eip,=,esp,[4],eip,=,4,esp,+=',
#                 '103,eip,=,esp,[4],eip,=,4,esp,+=',
#             ], []),
#         }))
#
#     with it('breaks up an existing block if there is a jmp into it'):
#         r = MockRadare(textwrap.dedent('''
#             0,eax,=
#             1,eax,=
#             2,eax,=
#             101,eip,=
#             esp,[4],eip,=,4,esp,+=
#         ''').strip().split('\n'), 100)
#         func = FuncsExtract(r).extract_funcs(100, ConstConstraint())[100][0]
#         expect(func.blocks).to(equal({
#             100: Block([
#                 '101,eip,=,0,eax,=',
#             ], [101]),
#             101: Block([
#                 '102,eip,=,1,eax,=',
#                 '103,eip,=,2,eax,=',
#                 '104,eip,=,101,eip,='
#             ], [101]),
#         }))
#
#     with it('breaks up an existing block if there is a conditional jmp into it'):
#         r = MockRadare(textwrap.dedent('''
#             0,eax,=
#             1,eax,=
#             2,eax,=
#             zf,?{,101,eip,=,}
#             esp,[4],eip,=,4,esp,+=
#         ''').strip().split('\n'), 100)
#         func = FuncsExtract(r).extract_funcs(100, ConstConstraint())[100][0]
#         expect(func.blocks).to(equal({
#             100: Block([
#                 '101,eip,=,0,eax,=',
#             ], [101]),
#             101: Block([
#                 '102,eip,=,1,eax,=',
#                 '103,eip,=,2,eax,=',
#                 '104,eip,=,zf,?{,101,eip,=,}'
#             ], [101, 104], ('zf', 0)),
#             104: Block([
#                 '105,eip,=,esp,[4],eip,=,4,esp,+='
#             ], []),
#         }))
#
#     with it('ignores conditional jmps if there are constant flags'):
#         r = MockRadare(textwrap.dedent('''
#             eax,eax,^=,$z,zf,=
#             zf,!,?{,200,eip,=,}
#             1,eax,=
#             esp,[4],eip,=,4,esp,+=
#         ''').strip().split('\n'), 100)
#         func = FuncsExtract(r).extract_funcs(100, ConstConstraint())[100][0]
#         expect(func.blocks).to(equal({
#             100: Block([
#                 '101,eip,=,eax,eax,^=,$z,zf,=',
#                 '102,eip,=,zf,!,?{,200,eip,=,}',
#                 '103,eip,=,1,eax,=',
#                 '104,eip,=,esp,[4],eip,=,4,esp,+=',
#             ], []),
#         }))
#
#     with it('breaks-up & re-analyzes existing block if the constraint is no longer constant'):
#         r = MockRadare(textwrap.dedent('''
#             eax,eax,^=,$z,zf,=
#             zf,!,?{,104,eip,=,}
#             ebx,eax,+=,$z,zf,=
#             101,eip,=
#             esp,[4],eip,=,4,esp,+=
#         ''').strip().split('\n'), 100)
#         func = FuncsExtract(r).extract_funcs(100, ConstConstraint())[100][0]
#         expect(func.blocks).to(equal({
#             100: Block([
#                 '101,eip,=,eax,eax,^=,$z,zf,=',
#             ], [101]),
#             101: Block([
#                 '102,eip,=,zf,!,?{,104,eip,=,}',
#             ], [104, 102], ('zf', 1)),
#             102: Block([
#                 '103,eip,=,ebx,eax,+=,$z,zf,=',
#                 '104,eip,=,101,eip,=',
#             ], [101]),
#             104: Block([
#                 '105,eip,=,esp,[4],eip,=,4,esp,+=',
#             ], []),
#         }))
#
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
