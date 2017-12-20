from expects import *

from analysis.constraint import ConstConstraint, DisjunctConstConstraint
from analysis.emu import update_radare_state
from analysis.specs._stub import *
from analysis.specs._utils import MockRadare

with description('update_radare_state'):
    with before.each:
        self.r = MockRadare(100, [])

    with it('sets vars'):
        c = ConstConstraint({'eax': 1})
        update_radare_state(self.r, DisjunctConstConstraint([c]), {})
        expect(self.r.emu.vars).to(have_key('eax', 1))

    with it('sets stack'):
        c = ConstConstraint()
        c.stack.values[(0, 4)] = 1
        update_radare_state(self.r, DisjunctConstConstraint([c]), {'esp': 4})
        expect(self.r.emu.mem.values).to(have_key((4, 4), 1))

    with it('sets memory with constant base'):
        c = ConstConstraint()
        c.mem_var = 0
        c.mem.values[(4, 4)] = 1
        update_radare_state(self.r, DisjunctConstConstraint([c]), {})
        expect(self.r.emu.mem.values).to(have_key((4, 4), 1))

    with it('sets memory with var base'):
        c = ConstConstraint()
        c.mem_var = 'eax_0'
        c.mem.values[(0, 4)] = 1
        update_radare_state(self.r, DisjunctConstConstraint([c]), {'eax': 4})
        expect(self.r.emu.mem.values).to(have_key((4, 4), 1))
