import re
import textwrap
import unittest

from sympy import sympify

from analysis.block import Block
from analysis.extract import FuncExtract
from analysis.symbolic import SymbolicEmu


class MockRadare:
    def __init__(self, instrs, base_addr):
        self.instrs = instrs
        self.base_addr = base_addr
        self.emu = SymbolicEmu()
        for reg in self.emu.regs:
            self.emu.regs[reg] = sympify(0)
        for i in range(0, 100, 4):
            self.emu.mem.values[(i, 4)] = sympify(0)

    def cmd(self, cmd):
        matches = re.match(r's (\d+)', cmd)
        if matches:
            self.emu.regs['eip'] = sympify(matches.group(1))
            return
        matches = re.match(r'aei|aeim|aeip', cmd)
        if matches:
            return
        matches = re.match(r'aer ([a-z]+)=(\d+)', cmd)
        if matches:
            self.emu.regs[matches.group(1)] = sympify(matches.group(2))
            return
        matches = re.match(r'aes', cmd)
        if matches:
            instr = self.instrs[int(self.emu.regs['eip']) - self.base_addr]
            self.emu.regs['eip'] += 1  # update eip first as esil assumes its updated
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
            return {name: val for name, val in self.emu.regs.items() if not name.startswith('$')}
        raise ValueError('cmd', cmd)


class TestExtractFuncs(unittest.TestCase):
    def test_simple(self):
        r = MockRadare(textwrap.dedent('''
            0,eax,=
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        funcs = FuncExtract(r).extract_funcs(100)
        self.assertEqual(funcs[0].blocks, {
            100: Block([
                '101,eip,=,0,eax,=',
                '102,eip,=,esp,[4],eip,=,4,esp,+='
            ], []),
        })

    def test_cond_jmp_existing(self):
        # test conditional jmp into middle of existing block to break up block
        r = MockRadare(textwrap.dedent('''
            0,eax,=
            1,eax,=
            2,eax,=
            zf,?{,101,eip,=,}
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        funcs = FuncExtract(r).extract_funcs(100, is_oep_func=False)
        self.assertEqual(funcs[0].blocks, {
            100: Block([
                '101,eip,=,0,eax,=',
            ], [101]),
            101: Block([
                '102,eip,=,1,eax,=',
                '103,eip,=,2,eax,=',
                '104,eip,=,zf,?{,101,eip,=,}'
            ], [101, 104], ('zf', False)),
            104: Block([
                '105,eip,=,esp,[4],eip,=,4,esp,+='
            ], []),
        })

    def test_cond_jmp_new(self):
        # test conditional jmp into new block to break up block
        r = MockRadare(textwrap.dedent('''
            0,eax,=
            zf,?{,103,eip,=,}
            1,eax,=
            2,eax,=
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        funcs = FuncExtract(r).extract_funcs(100, is_oep_func=False)
        self.assertEqual(funcs[0].blocks, {
            100: Block([
                '101,eip,=,0,eax,=',
                '102,eip,=,zf,?{,103,eip,=,}'
            ], [103, 102], ('zf', False)),
            102: Block([
                '103,eip,=,1,eax,=',
            ], [103]),
            103: Block([
                '104,eip,=,2,eax,=',
                '105,eip,=,esp,[4],eip,=,4,esp,+='
            ], []),
        })

    def test_cond_ret(self):
        # requires restoration of esp and identifying we landed on an existing addresses
        pass

    def test_fixed_jmp_const(self):
        # conditional jmp depends on constant flag
        r = MockRadare(textwrap.dedent('''
            eax,eax,^=
            zf,?{,103,eip,=,}
            1,eax,=
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        funcs = FuncExtract(r).extract_funcs(100, is_oep_func=False)
        self.assertEqual(funcs[0].blocks, {
            100: Block([
                '101,eip,=,eax,eax,^=',
                '102,eip,=,zf,?{,103,eip,=,}',
                '103,eip,=,1,eax,=',
                '104,eip,=,esp,[4],eip,=,4,esp,+=',
            ], []),
        })

    def test_fixed_jmp_no_longer_const(self):
        # conditional jmp flag is no longer constant
        r = MockRadare(textwrap.dedent('''
            eax,eax,^=
            $z,zf,=
            zf,?{,103,eip,=,}
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        funcs = FuncExtract(r).extract_funcs(100, is_oep_func=False)
        self.assertEqual(funcs[0].blocks, {
            100: Block([
                '101,eip,=,eax,eax,^=',
                '102,eip,=,$z,zf,=',
                '103,eip,=,zf,?{,103,eip,=,}',
            ], [103, 103], ('zf', False)),
            103: Block([
                '104,eip,=,esp,[4],eip,=,4,esp,+=',
            ], []),
        })

    def test_fixed_jmp_precond(self):
        # some flags are constant depending on conditional jmp location
        r = MockRadare(textwrap.dedent('''
            zf,?{,102,eip,=,}
            zf,?{,200,eip,=,}
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        funcs = FuncExtract(r).extract_funcs(100, is_oep_func=False)
        self.assertEqual(funcs[0].blocks, {
            100: Block([
                '101,eip,=,zf,?{,102,eip,=,}',
            ], [102, 101], ('zf', False)),
            101: Block([
                '102,eip,=,zf,?{,200,eip,=,}',
            ], [102]),
            102: Block([
                '103,eip,=,esp,[4],eip,=,4,esp,+=',
            ], []),
        })
