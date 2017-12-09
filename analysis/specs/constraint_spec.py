from unittest.mock import patch

from expects import *

from analysis.constraint import ConstConstraint
from analysis.specs._stub import *
from analysis.winapi import win_api

with description('ConstConstraint'):
    with it('initializes possible mem offsets to placeholders and flags to their initial values'):
        c = ConstConstraint.from_oep()
        expect(c.vars).to(equal({
            'eax': ('eax_0', 0), 'ecx': ('ecx_0', 0), 'edx': ('edx_0', 0), 'ebx': ('ebx_0', 0),
            'esp': ('esp_0', 0), 'ebp': ('ebp_0', 0), 'esi': ('esi_0', 0), 'edi': ('edi_0', 0),
            'eip': ('eip_0', 0),
            'cf': 0, 'pf': 1, 'af': 0, 'zf': 1, 'sf': 0, 'tf': 0, 'df': 0, 'of': 0,
        }))

    with context('__eq__'):
        with before.each:
            self.c1 = ConstConstraint()
            self.c2 = ConstConstraint()

        with it('equals only when vars are equal'):
            self.c1.vars = {'eax': 0}
            expect(self.c1).not_to(equal(self.c2))
            self.c2.vars = {'eax': 0}
            expect(self.c1).to(equal(self.c2))

        with it('equals only when stack is equal'):
            self.c1.stack.values = {(0, 4): 0}
            expect(self.c1).not_to(equal(self.c2))
            self.c2.stack.values = {(0, 4): 0}
            expect(self.c1).to(equal(self.c2))

        with it('equals only when mem is equal'):
            self.c1.mem.values = {(0, 4): 0}
            expect(self.c1).not_to(equal(self.c2))
            self.c2.mem.values = {(0, 4): 0}
            expect(self.c1).to(equal(self.c2))
            self.c1.mem_var = 'eax'
            expect(self.c1).not_to(equal(self.c2))

    with context('widen'):
        with before.each:
            self.c1 = ConstConstraint()
            self.c2 = ConstConstraint()

        with it('widens regs'):
            self.c1.vars = {'eax': 0, 'ebx': 1, 'ecx': 2}
            self.c2.vars = {'ebx': 2, 'ecx': 2, 'edx': 3}
            self.c1.widen(self.c2)
            expect(self.c1.vars).to(equal({'ecx': 2}))

        with it('widens stack'):
            self.c1.stack.values = {(0, 4): 0, (4, 4): 1, (6, 4): 2}
            self.c2.stack.values = {(4, 4): 2, (6, 4): 2, (12, 4): 3}
            self.c1.widen(self.c2)
            expect(self.c1.stack.values).to(equal({(6, 4): 2}))

        with it('widens mem'):
            self.c1.mem.values = {(0, 4): 0, (4, 4): 1, (6, 4): 2}
            self.c2.mem.values = {(4, 4): 2, (6, 4): 2, (12, 4): 3}
            self.c1.widen(self.c2)
            expect(self.c1.mem.values).to(equal({(6, 4): 2}))
            self.c1.mem_var = 'eax'
            self.c1.widen(self.c2)
            expect(self.c1.mem.values).to(equal({}))

    with context('step'):
        with before.each:
            self.c = ConstConstraint()

        with context('op'):
            with it('evals integer'):
                self.c.step(('eax', '=', 1))
                expect(self.c.vars['eax']).to(equal(1))

            with it('evals variable'):
                self.c.vars['eax'] = 1
                self.c.step(('ebx', '=', 'eax'))
                expect(self.c.vars['ebx']).to(equal(1))

            with it('evals $bxxx to 1 when there is borrow'):
                self.c.step(('eax', '=', '$b8', 0))
                expect(self.c.vars['eax']).to(equal(0))
                self.c.step(('eax', '=', '$b8', -1))
                expect(self.c.vars['eax']).to(equal(1))
                self.c.step(('eax', '=', '$b8', 0x1ff))
                expect(self.c.vars['eax']).to(equal(1))

            with it('sets $cxxx to 1 when there is borrow'):
                self.c.step(('eax', '=', '$c7', 0))
                expect(self.c.vars['eax']).to(equal(0))
                self.c.step(('eax', '=', '$c7', 0x1ff))
                expect(self.c.vars['eax']).to(equal(1))

            with it('does nothing for $p'):
                self.c.step(('eax', '=', '$p', 0))
                expect(self.c.vars).not_to(have_key('eax'))

            with it('sets $zf on integer'):
                self.c.step(('eax', '=', '$z', 0))
                expect(self.c.vars['eax']).to(equal(1))
                self.c.step(('eax', '=', '$z', 1))
                expect(self.c.vars['eax']).to(equal(0))

            with it('sets $zf to 0 when value involves `esp_0 + const`'):
                self.c.vars['esp'] = ('esp_0', 0)
                self.c.step(('eax', '=', '$z', 'esp'))
                expect(self.c.vars['eax']).to(equal(0))

            with it('does nothing for $s'):
                self.c.step(('eax', '=', '$s', 0))
                expect(self.c.vars).not_to(have_key('eax'))

            with it('does nothing for $o'):
                self.c.step(('eax', '=', '$o', 0))
                expect(self.c.vars).not_to(have_key('eax'))

            with it('negates boolean for !'):
                self.c.step(('eax', '=', '!', 0))
                expect(self.c.vars['eax']).to(equal(1))
                self.c.step(('eax', '=', '!', 1))
                expect(self.c.vars['eax']).to(equal(0))

            with context('and'):
                with it('ands integer vars'):
                    self.c.step(('eax', '=', '&', 0x12, 0x34))
                    expect(self.c.vars['eax']).to(equal(0x10))

            with context('or'):
                with it('ors integer vars'):
                    self.c.step(('eax', '=', '|', 0x12, 0x34))
                    expect(self.c.vars['eax']).to(equal(0x36))

            with context('xor'):
                with it('xors integer vars'):
                    self.c.step(('eax', '=', '^', 0x12, 0x34))
                    expect(self.c.vars['eax']).to(equal(0x26))

                with it('clears var when xoring with same value'):
                    self.c.step(('eax', '=', '^', 'eax', 'eax'))
                    expect(self.c.vars['eax']).to(equal(0))

            with context('add'):
                with it('adds integer vars'):
                    self.c.step(('eax', '=', '+', 1, 2))
                    expect(self.c.vars['eax']).to(equal(3))

                with it('adds mem offsets'):
                    self.c.vars['esp'] = ('esp_0', 0)
                    self.c.step(('eax', '=', '+', 'esp', 1))
                    expect(self.c.vars['eax']).to(equal(('esp_0', 1)))
                    self.c.step(('eax', '=', '+', 1, 'esp'))
                    expect(self.c.vars['eax']).to(equal(('esp_0', 1)))

            with context('sub'):
                with it('subs integer vars'):
                    self.c.step(('eax', '=', '-', 2, 1))
                    expect(self.c.vars['eax']).to(equal(1))

                with it('subs mem offsets'):
                    self.c.vars['esp'] = ('esp_0', 2)
                    self.c.step(('eax', '=', '-', 'esp', 1))
                    expect(self.c.vars['eax']).to(equal(('esp_0', 1)))

            with context('mul'):
                with it('muls integer vars'):
                    self.c.step(('eax', '=', '*', 2, 3))
                    expect(self.c.vars['eax']).to(equal(6))

            with it('raises error on unknown op'):
                expect(lambda: self.c.step(('eax', '=', '??', 'ebx'))).to(raise_error(ValueError))

        with context('assign'):
            with it('mods integer values if they are from registers'):
                self.c.step(('al_0', '=', (1 << 8) + 1))
                expect(self.c.vars['al_0']).to(equal(1))

            with it('does not mod values that are not from registers'):
                self.c.step(('temp_0', '=', (1 << 8) + 1))
                expect(self.c.vars['temp_0']).to(equal((1 << 8) + 1))

            with it('assigns mem offsets'):
                self.c.vars['esp'] = ('esp_0', 0)
                self.c.step(('eax', '=', 'esp'))
                expect(self.c.vars['eax']).to(equal(('esp_0', 0)))

            with it('removes non-constants'):
                self.c.step(('eax', '=', 'ebx'))
                expect(self.c.vars).to_not(have_key('eax'))

        with context('assign to super-register'):
            with it('assigns when parent register and value are integers'):
                self.c.vars['eax'] = 0xffffffff
                self.c.step(('eax', 'l=', 1))
                expect(self.c.vars['eax']).to(equal(0xffffff01))
                self.c.vars['eax'] = 0xffffffff
                self.c.step(('eax', 'h=', 1))
                expect(self.c.vars['eax']).to(equal(0xffff01ff))
                self.c.vars['eax'] = 0xffffffff
                self.c.step(('eax', 'x=', 1))
                expect(self.c.vars['eax']).to(equal(0xffff0001))

            with it('removes non-integers'):
                self.c.step(('eax', 'x=', 1))
                expect(self.c.vars).to_not(have_key('eax'))

        with context('assign to sub-register'):
            with it('assigns when value is an integer'):
                self.c.step(('al', '=l', 0x01020304))
                expect(self.c.vars['al']).to(equal(0x04))
                self.c.step(('ah', '=h', 0x01020304))
                expect(self.c.vars['ah']).to(equal(0x03))
                self.c.step(('ax', '=x', 0x01020304))
                expect(self.c.vars['ax']).to(equal(0x0304))

            with it('removes non-integers'):
                self.c.vars['esp'] = ('esp_0', 0)
                self.c.step(('al', '=l', 'esp'))
                expect(self.c.vars).to_not(have_key('eax'))

        with context('read memory'):
            with it('reads from stack'):
                self.c.vars['esp'] = ('esp_0', 0)
                self.c.stack.values[(0, 4)] = 1
                self.c.step(('eax', '=[4]', 'esp'))
                expect(self.c.vars['eax']).to(equal(1))

            with it('reads from memory'):
                self.c.mem.values[(0, 4)] = 1
                self.c.step(('eax', '=[4]', 0))
                expect(self.c.vars['eax']).to(equal(1))

            with it('does not read from memory when mem var is different'):
                self.c.vars['eax'] = ('eax_0', 0)
                self.c.mem.values[(0, 4)] = 1
                self.c.step(('eax', '=[4]', 'eax'))
                expect(self.c.vars).to_not(have_key('eax'))

            with it('removes when nothing is read'):
                self.c.vars['esp'] = ('esp_0', 0)
                self.c.step(('eax', '=[4]', 'esp'))
                expect(self.c.vars).to_not(have_key('eax'))

        with context('write memory'):
            with it('writes to stack'):
                self.c.vars['esp'] = ('esp_0', 0)
                self.c.step(('esp', '[4]=', 1))
                expect(self.c.stack.values).to(equal({(0, 4): 1}))

            with it('writes to memory'):
                self.c.step((1, '[4]=', 1))
                expect(self.c.mem.values).to(equal({(1, 4): 1}))

            with it('invalidates previous memory and writes to new memory if mem var has changed'):
                self.c.mem.values[(0, 4)] = 1
                self.c.vars['eax'] = ('eax_0', 1)
                self.c.step(('eax', '[4]=', 1))
                expect(self.c.mem.values).to(equal({(1, 4): 1}))

        with it('raises error on unknown assign'):
            expect(lambda: self.c.step((1, '??=', 1))).to(raise_error(ValueError))

    with context('step_api_jmp'):
        with before.each:
            self.patcher = patch.object(win_api, 'get_stack_change', return_value=0)
            self.patcher.__enter__()
        with after.all:
            self.patcher.__exit__()

        with it('invalidates registers'):
            self.c.step_api_jmp('some_lib', 'some_method')
            expect(self.c.vars).to_not(have_key('eax'))

        with it('updates esp'):
            self.c.vars['esp'] = ('esp_0', 0)
            self.c.step_api_jmp('some_lib', 'some_method')
            expect(self.c.vars['esp']).to(equal(('esp_0', 4)))

        with it('invalidates overlapping stack values since can be changed by call'):
            self.c.stack.values[(-5, 4)] = 1
            self.c.stack.values[(-4, 4)] = 2
            self.c.vars['esp'] = ('esp_0', -8)
            self.c.step_api_jmp('some_lib', 'some_method')
            expect(self.c.stack.values).to(equal({(-4, 4): 2}))

        with it('invalidates all stack values if esp is unknown'):
            self.c.stack.values[(0, 4)] = 1
            self.c.vars['esp'] = ('eax_0', 0)
            self.c.step_api_jmp('some_lib', 'some_method')
            expect(self.c.stack.values).to(equal({}))

        with it('invalidates memory'):
            self.c.mem.values[(0, 4)] = 1
            self.c.step_api_jmp('some_lib', 'some_method')
            expect(self.c.mem.values).to(equal({}))