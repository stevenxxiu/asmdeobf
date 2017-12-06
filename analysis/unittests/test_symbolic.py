import unittest
from unittest.mock import patch
from sympy import Symbol

from analysis.symbolic import SymbolicEmu, SymbolNames
from analysis.winapi import win_api


class TestSymbolicEmu(unittest.TestCase):
    def setUp(self):
        self.emu = SymbolicEmu(SymbolNames())

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

    def test_api_jmp(self):
        with patch.object(win_api, 'get_stack_change', return_value=0):
            self.emu.mem.values[0, 0] = 1
            self.emu.stack.values[-5, 4] = 1
            self.emu.stack.values[-4, 4] = 2
            self.emu.regs['esp'] -= 8
            self.emu.step_api_jmp('some_lib', 'some_method')
            self.assertEqual(self.emu.mem.values, {})
            # any overlapping stack value is invalidated since it can be changed by the call
            self.assertEqual(self.emu.stack.values, {(-4, 4): 2})
            self.assertEqual(self.emu.regs['eax'], Symbol('eax_1'))
            self.assertEqual(self.emu.regs['esp'], Symbol('esp_0') - 4)

    def test_api_jmp_unknown_stack(self):
        with patch.object(win_api, 'get_stack_change', return_value=0):
            self.emu.stack.values[-4, 4] = 2
            self.emu.regs['esp'] = self.emu.names['esp']
            self.emu.step_api_jmp('some_lib', 'some_method')
            self.assertEqual(self.emu.stack.values, {})
