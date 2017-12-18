import re
import textwrap

from expects import *

from analysis.block import Block
from analysis.constraint import ConstConstraint, DisjunctConstConstraint
from analysis.extract import FuncExtract
from analysis.specs._stub import *


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


with description('FuncExtract'):
    with before.each:
        self.r = MockRadare([], 100)
        self.func_extract = FuncExtract(self.r, 100, {}, DisjunctConstConstraint(), ())

    with description('_update_radare_state'):
        with it('sets vars'):
            c = ConstConstraint({'eax': 1})
            self.func_extract._update_radare_state(DisjunctConstConstraint([c]))
            expect(self.r.emu.vars).to(have_key('eax', 1))

        with it('sets stack'):
            self.func_extract.initial_vars['esp_0'] = 4
            c = ConstConstraint()
            c.stack.values[(0, 4)] = 1
            self.func_extract._update_radare_state(DisjunctConstConstraint([c]))
            expect(self.r.emu.mem.values).to(have_key((4, 4), 1))

        with it('sets memory with constant base'):
            c = ConstConstraint()
            c.mem_var = 0
            c.mem.values[(4, 4)] = 1
            self.func_extract._update_radare_state(DisjunctConstConstraint([c]))
            expect(self.r.emu.mem.values).to(have_key((4, 4), 1))

        with it('sets memory with var base'):
            self.func_extract.initial_vars['eax_0'] = 4
            c = ConstConstraint()
            c.mem_var = 'eax_0'
            c.mem.values[(0, 4)] = 1
            self.func_extract._update_radare_state(DisjunctConstConstraint([c]))
            expect(self.r.emu.mem.values).to(have_key((4, 4), 1))

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
