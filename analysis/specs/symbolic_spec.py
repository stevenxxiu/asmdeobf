from unittest.mock import patch

from expects import *
from sympy import Symbol, sympify

from analysis.specs._stub import *
from analysis.symbolic import SymbolicEmu, SymbolNames
from analysis.winapi import win_api

with description('SymbolicEmu'):
    with before.each:
        self.emu = SymbolicEmu(SymbolNames())

    with it('loads constants correctly'):
        self.emu.step('0,eax,=')
        expect(self.emu.regs['eax']).to(equal(0))
        self.emu.step('0x0,eax,=')
        expect(self.emu.regs['eax']).to(equal(0))
        self.emu.step('$0,zf,=')
        expect(self.emu.regs['zf']).to(equal(0))
        self.emu.step('$1,zf,=')
        expect(self.emu.regs['zf']).to(equal(1))

    with context('flags'):
        with it('sets $bxxx to 1 when there is borrow'):
            self.emu.flag_val = sympify(0)
            self.emu.step('$b8,cf,=')
            expect(self.emu.regs['cf']).to(equal(0))
            self.emu.flag_val = sympify(-1)
            self.emu.step('$b8,cf,=')
            expect(self.emu.regs['cf']).to(equal(1))
            self.emu.flag_val = sympify(0x1FF)
            self.emu.step('$b8,cf,=')
            expect(self.emu.regs['cf']).to(equal(1))

        with it('sets $cxxx to 1 when there is borrow'):
            self.emu.flag_val = sympify(0)
            self.emu.step('$c7,cf,=')
            expect(self.emu.regs['cf']).to(equal(0))
            self.emu.flag_val = sympify(0x1FF)
            self.emu.step('$c7,cf,=')
            expect(self.emu.regs['cf']).to(equal(1))

        with it('sets $zf to 1 when register is 0'):
            self.emu.flag_val = sympify(0)
            self.emu.step('$z,zf,=')
            expect(self.emu.regs['zf']).to(equal(1))

    with context('assign'):
        with it('mods integer values'):
            self.emu.step('0x100,al,=')
            expect(self.emu.regs['al']).to(equal(0))

        with it('affects superset registers for integer values'):
            self.emu.step('0,eax,=')
            self.emu.step('1,al,=')
            expect(self.emu.regs['al']).to(equal(1))
            expect(self.emu.regs['ah']).to(equal(0))
            expect(self.emu.regs['ax']).to(equal(1))
            expect(self.emu.regs['eax']).to(equal(1))

        with it('affects subset registers for integer values'):
            self.emu.step('0,eax,=')
            expect(self.emu.regs['al']).to(equal(0))
            expect(self.emu.regs['ah']).to(equal(0))
            expect(self.emu.regs['ax']).to(equal(0))
            expect(self.emu.regs['eax']).to(equal(0))

    with context('add'):
        with it('adds using sympy expressions'):
            self.emu.step('1,eax,+=')
            expect(self.emu.regs['eax']).to(equal(Symbol('eax_0') + 1))

    with context('inc'):
        with it('increments using sympy expressions'):
            self.emu.step('eax,++=')
            expect(self.emu.regs['eax']).to(equal(Symbol('eax_0') + 1))

    with context('xor'):
        with it('clears register when xoring with same value'):
            self.emu.step('eax,eax,^=')
            expect(self.emu.regs['eax']).to(equal(0))

    with context('memory'):
        with context('converts memory offsets'):
            with it('has register of 0 for integers'):
                expect(self.emu._conv_mem_access(sympify(1))).to(equal((0, 1)))

            with it('has register for register + offset'):
                expect(self.emu._conv_mem_access(sympify('esp_0'))).to(equal((Symbol('esp_0'), 0)))
                expect(self.emu._conv_mem_access(sympify('esp_0') + 4)).to(equal((Symbol('esp_0'), 4)))

            with it('returns None for unknown expressions'):
                expect(self.emu._conv_mem_access(sympify('esp_0') + sympify('ebp_0'))).to(equal((None, None)))

        with it('sets and reads stack values to the same expression'):
            self.emu.step('4,esp,+=')
            self.emu.step('1,esp,=[4]')
            self.emu.step('esp,[4],eax,=')
            expect(self.emu.regs['eax']).to(equal(1))

        with it('sets and reads mem values to the same expression'):
            self.emu.step('4,ebx,+=')
            self.emu.step('1,ebx,=[4]')
            self.emu.step('ebx,[4],eax,=')
            expect(self.emu.regs['eax']).to(equal(1))

    with it('returns a new variable for unknown memory'):
        self.emu.step('eax,ebx,+=')
        self.emu.step('ebx,[4],eax,=')
        expect(self.emu.regs['eax']).to(equal(Symbol('mem_0')))

    with context('api jmp'):
        with before.each:
            self.patcher = patch.object(win_api, 'get_stack_change', return_value=0)
            self.patcher.__enter__()
        with after.all:
            self.patcher.__exit__()

        with it('invalidates registers'):
            self.emu.step_api_jmp('some_lib', 'some_method')
            expect(self.emu.regs['eax']).to(equal(Symbol('eax_1')))

        with it('updates stack'):
            self.emu.step_api_jmp('some_lib', 'some_method')
            expect(self.emu.regs['esp']).to(equal(Symbol('esp_0') + 4))

        with it('invalidates overlapping stack values since can be changed by call'):
            self.emu.stack.values[-5, 4] = 1
            self.emu.stack.values[-4, 4] = 2
            self.emu.regs['esp'] -= 8
            self.emu.step_api_jmp('some_lib', 'some_method')
            expect(self.emu.stack.values).to(equal({(-4, 4): 2}))

        with it('invalidates all stack values if unknown'):
            self.emu.stack.values[0, 0] = 1
            self.emu.regs['esp'] += Symbol('eax_0')
            self.emu.step_api_jmp('some_lib', 'some_method')
            expect(self.emu.stack.values).to(equal({}))

        with it('invalidates memory'):
            self.emu.mem.values[0, 0] = 1
            self.emu.step_api_jmp('some_lib', 'some_method')
            expect(self.emu.mem.values).to(equal({}))
