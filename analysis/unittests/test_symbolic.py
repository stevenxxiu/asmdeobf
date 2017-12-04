import unittest

from analysis.symbolic import SymbolicEmu, SymbolNames


class TestSymbolicEmu(unittest.TestCase):
    def setUp(self):
        self.emu = SymbolicEmu(True, SymbolNames())

    def test_const(self):
        self.emu.step('0,eax,=')
        self.assertEqual(self.emu.regs['eax'], 0)
        self.emu.step('0x0,eax,=')
        self.assertEqual(self.emu.regs['eax'], 0)
        self.emu.step('$0,$z,=')
        self.assertEqual(self.emu.regs['$z'], 0)
        self.emu.step('$1,$z,=')
        self.assertEqual(self.emu.regs['$z'], 1)

    def test_propagate(self):
        self.emu.step('0,eax,=')
        self.assertEqual(self.emu.regs['al'].name, 'al_1')
        self.assertEqual(self.emu.regs['ah'].name, 'ah_1')
        self.assertEqual(self.emu.regs['ax'].name, 'ax_1')
        self.assertEqual(self.emu.regs['eax'], 0)

    def test_add(self):
        self.emu.step('1,eax,+=')
        self.assertEqual(str(self.emu.regs['eax']), 'eax_0 + 1')

    def test_xor(self):
        self.emu.step('eax,eax,^=')
        self.assertEqual(self.emu.regs['eax'], 0)
        self.assertEqual(self.emu.regs['$z'], 0)

    def test_mem(self):
        self.emu.step('1,esp,=[4]')
        self.emu.step('esp,[4],eax,=')
        self.assertEqual(self.emu.regs['eax'], 1)
        self.emu.step('4,esp,+=')
        self.emu.step('2,esp,=[4]')
        self.emu.step('esp,[4],eax,=')
        self.assertEqual(self.emu.regs['eax'], 2)
        self.emu.step('ebx,[4],eax,=')
        self.assertEqual(self.emu.regs['eax'].name, 'mem_2')
