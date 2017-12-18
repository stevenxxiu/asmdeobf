import re

from analysis.block import Block
from analysis.func import Function


class FuncExtract:
    def __init__(self, r, start_addr, funcs, constraint, end_addrs):
        self.r = r
        self.start_addr = start_addr
        self.funcs = funcs
        self.start_constraint = constraint
        self.end_constraint = None
        self.end_addrs = set(end_addrs)
        self.initial_vars = {}

        self.addr_to_constraint = {}  # {addr: constraint}
        self.addr_to_block = {}  # {addr: (block, i)}
        self.stack = []  # [(addr, state)]

    def _extract_esil(self, addr):
        # update eip so the instruction is more complete for conditional jmps and call
        res = self.r.cmdj(f'pdj 1 @ {addr}')[0]
        return f'{addr + res["size"]},eip,=,{res["esil"]}'

    def _eval_cons_val(self, val):
        return val if isinstance(val, int) else self.initial_vars[val[0]] + val[1]

    def _update_radare_state(self, con):
        con = con.const_cons[0]
        for name, val in con.vars.items():
            self.r.cmd(f'aer {name}={self._eval_cons_val(val)}')
        for (offset, size), val in con.stack.values.items():
            self.r.cmd(f'ae {self._eval_cons_val(val)},{self.initial_vars["esp_0"] + offset},=[{size}]')
        mem_base = con.mem_var and self.initial_vars[con.mem_var]
        for (offset, size), val in con.mem.values.items():
            self.r.cmd(f'ae {self._eval_cons_val(val)},{mem_base + offset},=[{size}]')

    def _stack_append(self, addr, constraint_):
        self.stack.append((addr, constraint_))
        self.addr_to_constraint[addr] = constraint_

    def _extract_block(self, cur_addr, con):
        con.step(('eip', '=', cur_addr))
        self._update_radare_state(con)
        block = Block()
        while True:
            cur_addr = state.vars['eip']
            if not cur_addr.is_Integer or cur_addr in self.end_addrs:
                con = ConstConstraint.from_state(state)
                if self.end_constraint is None:
                    self.end_constraint = con
                else:
                    self.end_constraint.widen(con)
                break
            cur_addr = int(cur_addr)

            # if address is already found (through conditional jmps)
            if cur_addr in self.addr_to_block:
                block.children = [cur_addr]
                block, i = self.addr_to_block[cur_addr]
                con = ConstConstraint.from_state(state)
                prev_constraint = self.addr_to_constraint[self.block_to_addr[(id(block), 0)]]
                if i == 0:
                    con.widen(prev_constraint)
                if i != 0 or con != prev_constraint:
                    # remove old block
                    addrs = []
                    for j in range(len(block.instrs)):
                        self.addr_to_block.pop(addrs[-1])

                    # add new block (slice of old block until i)
                    new_block = Block(children=[cur_addr])
                    for addr, instr in zip(addrs[:i], block.instrs[:i]):
                        self.block_append_instr(new_block, addr, instr)

                    # update constraints & re-analyze
                    prev_state = prev_constraint.to_state(self.names)
                    for instr in block.instrs[:i]:
                        prev_state.step(instr)
                    con.widen(prev_constraint)
                    self._stack_append(cur_addr, con)
                break

            # append instruction
            instr = self._extract_esil(cur_addr)
            self.block_append_instr(block, cur_addr, instr)

            # check if we have a conditional jmp
            matches = re.match(r'(\d+),eip,=,(\wf),(!,)?\?{,(\d+),eip,=,}', instr)
            if matches:
                flag = matches.group(2)
                if not state.vars[flag].is_Integer:
                    is_negated = bool(matches.group(3))
                    # explore remaining code first before exploring jmp
                    con = ConstConstraint.from_state(state)
                    con.vars[flag] = sympify(int(not is_negated))
                    self._stack_append(int(matches.group(4)), con)
                    con = ConstConstraint.from_state(state)
                    con.vars[flag] = sympify(int(is_negated))
                    self._stack_append(int(matches.group(1)), con)
                    block.condition = (flag, int(is_negated))
                    block.children = [int(matches.group(4)), int(matches.group(1))]
                    break

            # check if instruction is a call to api
            matches = re.match(r'(\d+),eip,=,eip,4,esp,-=,esp,=\[\],(\d+),eip,=', instr)
            if matches:
                ret_addr, call_addr = matches.group(1), matches.group(2)
                matches = re.match(r'(0x\d+),\[\],eip,=', self.r.cmdj(f'pdj 1 @ {call_addr}')[0]['esil'])
                if matches:
                    api_addr = matches.group(1)
                    matches = re.match(r'sym\.imp\.(\S+)_(\S+)$', self.r.cmd(f'fd {api_addr}'))
                    if matches:
                        # end current block to aid in de-obfuscation
                        lib_name, api_name = matches.group(1), matches.group(2)
                        state.step_api_jmp(lib_name, api_name)
                        self._stack_append(int(ret_addr), state)
                        block.children = [int(ret_addr)]
                        break

            # check if instruction is a call to a proc
            # check if function was already analyzed

            state.step(instr)
            self.r.cmd('aes')

    def extract(self):
        self._stack_append(self.start_addr, self.start_constraint)
        self.r.cmd('aei')
        self.r.cmd('aeim')
        self.initial_vars = {f'{key}_0': val for key, val in self.r.cmdj(f'aerj')}
        while self.stack:
            self._extract_block(*self.stack.pop())
        addrs = {self.start_addr}
        for block, i in self.addr_to_block.values():
            addrs.update(block.children)
        func = Function(self.start_addr, {addr: self.addr_to_block[addr][0] for addr in addrs})
        self.funcs[self.start_addr] = func, self.end_constraint


class FuncsExtract:
    def __init__(self, r):
        self.r = r

    def extract_funcs(self, addr, constraint, end_addrs=()):
        funcs = {}
        FuncExtract(self.r, addr, funcs, constraint, end_addrs).extract()
        return funcs
