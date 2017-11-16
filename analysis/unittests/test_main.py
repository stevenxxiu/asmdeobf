import re
import textwrap
import unittest

from analysis.main import Block, FuncExtract


class MockRadare:
    def __init__(self, instrs, base_addr):
        self.instrs = instrs
        self.base_addr = base_addr
        self.regs = {'eax': 1, '$z': 0, 'eip': 0, 'esp': 0}
        self.mem = [0] * 64

    def _conv_val(self, val):
        return val if isinstance(val, int) else self.regs[val]

    def run_instr(self, instrs):
        instr_stack = []
        condition = True
        for instr in instrs.split(','):
            if not condition:
                continue
            if str.isdecimal(instr):
                instr_stack.append(int(instr))
            elif instr.startswith('0x'):
                instr_stack.append(int(instr, 16))
            elif instr in (
                'al', 'ah', 'ax', 'eax',
                'cl', 'ch', 'cx', 'ecx',
                'dl', 'dh', 'dx', 'edx',
                'bl', 'bh', 'bx', 'ebx',
                'sp', 'esp',
                'bp', 'ebp',
                'si', 'esi',
                'di', 'edi',
                'eip',
                'cf', 'pf', 'af', 'zf', 'sf', 'tf', 'df', 'of',
            ):
                instr_stack.append(instr)
            elif instr.startswith('$'):
                instr_stack.append(self.regs[instr])
            elif instr == '=':
                reg, val = instr_stack.pop(), instr_stack.pop()
                self.regs[reg] = self._conv_val(val)
            elif instr == '+=':
                # ignores flags for simplicity
                reg, val = instr_stack.pop(), instr_stack.pop()
                self.regs[reg] += self._conv_val(val)
            elif instr == '^=':
                # ignores flags for simplicity except zf
                reg, val = instr_stack.pop(), instr_stack.pop()
                self.regs[reg] ^= self._conv_val(val)
                self.regs['zf'] = self.regs[reg] = 0
            elif instr == '=[4]':
                addr, val = instr_stack.pop(), instr_stack.pop()
                self.mem[self._conv_val(addr)] = val
            elif instr == '[4]':
                instr_stack.append(self.mem[self._conv_val(instr_stack.pop())])
            elif instr == '?{':
                condition = self._conv_val(instr_stack.pop())
            elif instr == '}':
                condition = True
            else:
                raise ValueError('instr', instr)

    def cmd(self, cmd):
        matches = re.match(r's (\d+)', cmd)
        if matches:
            self.regs['eip'] = int(matches.group(1))
            return
        matches = re.match(r'ae (.+)', cmd)
        if matches:
            self.run_instr(matches.group(1))
            return
        matches = re.match(r'aei|aeim|aeip', cmd)
        if matches:
            return
        matches = re.match(r'aer ([$a-z]+)$', cmd)
        if matches:
            return f'0x{self.regs[matches.group(1)]:08x}'
        matches = re.match(r'aer ([$a-z]+)=(\d+)', cmd)
        if matches:
            self.regs[matches.group(1)] = int(matches.group(2))
            return
        matches = re.match(r'aes', cmd)
        if matches:
            instr = self.instrs[self.regs['eip'] - self.base_addr]
            self.regs['eip'] += 1  # update eip first as esil assumes its updated
            self.run_instr(instr)
            return
        raise ValueError('cmd', cmd)

    def cmdj(self, cmd):
        matches = re.match(r'pdj 1 @ (\d+)', cmd)
        if matches:
            return [{'esil': self.instrs[int(matches.group(1)) - self.base_addr], 'size': 1}]
        matches = re.match(r'aerj', cmd)
        if matches:
            return self.regs
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
            eax,1,=
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 100)
        funcs = FuncExtract(r).extract_funcs(100, is_oep_func=False)
        self.assertEqual(funcs[0].blocks, {
            100: Block([
                '101,eip,=,eax,eax,^=',
                '102,eip,=,zf,?{,103,eip,=,}',
                '103,eip,=,eax,1,=',
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
