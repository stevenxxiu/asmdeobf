import re
import textwrap
import unittest

from analysis.main import extract_funcs, Block


class MockRadare:
    def __init__(self, instrs, base_addr):
        self.instrs = instrs
        self.base_addr = base_addr
        self.regs = {'eip': 0, 'esp': 0}
        self.mem = [0] * 64

    def run_instr(self, instrs):
        instr_stack = []
        for instr in instrs.split(','):
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
            elif instr == '=':
                reg, val = instr_stack.pop(), instr_stack.pop()
                self.regs[reg] = val
            elif instr == '+=':
                reg, val = instr_stack.pop(), instr_stack.pop()
                self.regs[reg] += val
            elif instr == '=[4]':
                addr = instr_stack.pop()
                addr = addr if isinstance(addr, int) else self.regs[addr]
                self.mem[addr] = instr_stack.pop()
            elif instr == '[4]':
                addr = instr_stack.pop()
                addr = addr if isinstance(addr, int) else self.regs[addr]
                instr_stack.append(self.mem[addr])
            else:
                raise ValueError('instr')

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
        matches = re.match(r'aer (\w+)', cmd)
        if matches:
            return f'0x{self.regs[matches.group(1)]:08x}'
        matches = re.match(r'aer (\w+)=(\d+)', cmd)
        if matches:
            self.regs[matches.group(1)] = int(matches.group(2))
            return
        matches = re.match(r'aes', cmd)
        if matches:
            instr = self.instrs[self.regs['eip'] - self.base_addr]
            self.regs['eip'] += 1  # update eip first as esil assumes its updated
            self.run_instr(instr)
            return
        raise ValueError('cmd')

    def cmdj(self, cmd):
        matches = re.match(r'pdj 1 @ (\d+)', cmd)
        if matches:
            return [{'esil': self.instrs[int(matches.group(1)) - self.base_addr], 'size': 1}]
        raise ValueError('cmd')


class TestExtractFuncs(unittest.TestCase):
    # XXX for conditional jmps test jmping to existing address and jmping to new address

    def test_simple(self):
        r = MockRadare(textwrap.dedent('''
            eax,0,=
            esp,[4],eip,=,4,esp,+=
        ''').strip().split('\n'), 0x100)
        funcs = extract_funcs(r, 0x100)
        self.assertEqual(funcs[0x100], Block([0x100, 0x101], [
            '257,eip,=,eax,0,=',
            '258,eip,=,esp,[4],eip,=,4,esp,+='
        ], []))
