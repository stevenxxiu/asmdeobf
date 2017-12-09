import re

from sympy import Symbol, sympify

from analysis.block import Block
from analysis.constraint import ConstConstraint
from analysis.func import Function


class FuncExtract:
    def __init__(self, r, start_addr, funcs, constraint, end_addrs):
        self.r = r
        self.start_addr = start_addr
        self.funcs = funcs
        self.start_constraint = constraint
        self.end_constraint = None
        self.end_addrs = set(end_addrs)

        self.addr_to_constraint = {}  # {addr: constraint}
        self.addr_to_block = {}  # {addr: (block, i)}
        self.block_to_addr = {}  # {(block, i): addr}
        self.stack = []  # [(addr, state)]
        self.esp_0 = None

    def extract_esil(self, addr):
        # update eip to facilitate analysis of conditional jmps and call
        res = self.r.cmdj(f'pdj 1 @ {addr}')[0]
        return f'{addr + res["size"]},eip,=,{res["esil"]}'

    def block_append_instr(self, block, addr, instr):
        self.addr_to_block[addr] = (block, len(block.instrs))
        self.block_to_addr[(id(block), len(block.instrs))] = addr
        block.instrs.append(instr)

    def stack_append(self, addr, constraint_):
        self.stack.append((addr, constraint_))
        self.addr_to_constraint[addr] = constraint_

    def extract_block(self, cur_addr, constraint):
        constraint.regs['eip'] = sympify(cur_addr)
        state = constraint.to_state(self.names)
        block = Block()

        # update radare state
        for name, val in state.regs.items():
            val = val.subs(Symbol('esp_0'), self.esp_0)
            if not name.startswith('$') and val.is_Integer:
                self.r.cmd(f'aer {name}={val}')
        for (offset, size), val in state.stack.values.items():
            if val.is_Integer:
                self.r.cmd(f'ae {val},{self.esp_0 + offset},=[{size}]')
        self.r.cmd(f's {cur_addr}')
        self.r.cmd('aeip')

        while True:
            cur_addr = state.regs['eip']
            if not cur_addr.is_Integer or cur_addr in self.end_addrs:
                constraint = ConstConstraint.from_state(state)
                if self.end_constraint is None:
                    self.end_constraint = constraint
                else:
                    self.end_constraint.widen(constraint)
                break
            cur_addr = int(cur_addr)

            # if address is already found (through conditional jmps)
            if cur_addr in self.addr_to_block:
                block.children = [cur_addr]
                block, i = self.addr_to_block[cur_addr]
                constraint = ConstConstraint.from_state(state)
                prev_constraint = self.addr_to_constraint[self.block_to_addr[(id(block), 0)]]
                if i == 0:
                    constraint.widen(prev_constraint)
                if i != 0 or constraint != prev_constraint:
                    # remove old block
                    addrs = []
                    for j in range(len(block.instrs)):
                        addrs.append(self.block_to_addr[(id(block), j)])
                        self.addr_to_block.pop(addrs[-1])
                        self.block_to_addr.pop((id(block), j))

                    # add new block (slice of old block until i)
                    new_block = Block(children=[cur_addr])
                    for addr, instr in zip(addrs[:i], block.instrs[:i]):
                        self.block_append_instr(new_block, addr, instr)

                    # update constraints & re-analyze
                    prev_state = prev_constraint.to_state(self.names)
                    for instr in block.instrs[:i]:
                        prev_state.step(instr)
                    constraint.widen(prev_constraint)
                    self.stack_append(cur_addr, constraint)
                break

            # append instruction
            instr = self.extract_esil(cur_addr)
            self.block_append_instr(block, cur_addr, instr)

            # check if we have a conditional jmp
            matches = re.match(r'(\d+),eip,=,(\wf),(!,)?\?{,(\d+),eip,=,}', instr)
            if matches:
                flag = matches.group(2)
                if not state.regs[flag].is_Integer:
                    is_negated = bool(matches.group(3))
                    # explore remaining code first before exploring jmp
                    constraint = ConstConstraint.from_state(state)
                    constraint.regs[flag] = sympify(int(not is_negated))
                    self.stack_append(int(matches.group(4)), constraint)
                    constraint = ConstConstraint.from_state(state)
                    constraint.regs[flag] = sympify(int(is_negated))
                    self.stack_append(int(matches.group(1)), constraint)
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
                        self.stack_append(int(ret_addr), state)
                        block.children = [int(ret_addr)]
                        break

            # check if instruction is a call to a proc
            # check if function was already analyzed

            state.step(instr)
            self.r.cmd('aes')

    def extract(self):
        self.stack_append(self.start_addr, self.start_constraint)
        self.r.cmd('aei')
        self.r.cmd('aeim')
        self.esp_0 = self.r.cmdj(f'aerj')['esp']
        while self.stack:
            self.extract_block(*self.stack.pop())
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
