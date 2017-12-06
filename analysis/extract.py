import re

from sympy import Symbol, sympify

from analysis.block import Block
from analysis.func import Function
from analysis.symbolic import ConstConstraint, SymbolNames


class FuncExtract:
    def __init__(self, r, start_addr, funcs, constraint, end_addrs):
        self.r = r
        self.start_addr = start_addr
        self.funcs = funcs
        self.constraint = constraint
        self.end_addrs = set(end_addrs)

        self.addr_to_constraint = {}  # {addr: constraint}
        self.addr_to_block = {}  # {addr: (block, i)}
        self.block_to_addr = {}  # {(block, i): addr}
        self.names = SymbolNames()
        self.stack = []  # [(addr, state)]
        self.esp_0 = None

    def extract_esil(self, addr):
        # update eip to facilitate analysis of conditional jmps and call
        res = self.r.cmdj(f'pdj 1 @ {addr}')[0]
        return f'{addr + res["size"]},eip,=,{res["esil"]}'

    def stack_append(self, addr, constraint_):
        self.stack.append((addr, constraint_))
        self.addr_to_constraint[addr] = constraint_

    def extract_block(self, cur_addr, constraint):
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
            if not cur_addr.is_Integer == 0:
                self.end_addrs.add(int(cur_addr))
                break
            cur_addr = int(cur_addr)

            # if address is already found (through conditional jmps)
            if cur_addr in self.addr_to_block:
                block.children = [cur_addr]
                block, i = self.addr_to_block[cur_addr]

                # merge previous constraints & re-analyze
                prev_constraint = self.addr_to_constraint[self.block_to_addr[block, 0]]
                if i != 0 or prev_constraint != constraint:
                    prev_state = prev_constraint.to_state(self.names)
                    for instr in block.instrs:
                        prev_state.step(instr)
                    prev_constraint.widen(constraint)
                    self.stack_append(cur_addr, prev_constraint)

                # split block in 2
                if i == 0:
                    break
                n = len(block.instrs)
                new_block = Block(block.instrs[:i], [cur_addr])
                block.instrs = block.instrs[i:]
                for j in range(i):
                    self.addr_to_block[self.block_to_addr[(id(block), j)]] = new_block, j
                for j in range(i, n):
                    self.addr_to_block[self.block_to_addr[(id(block), j)]] = block, j - i
                for j in range(i):
                    self.block_to_addr[(id(new_block), j)] = self.block_to_addr.pop((id(block), j))
                for j in range(i, n):
                    self.block_to_addr[(id(block), j - i)] = self.block_to_addr.pop((id(block), j))
                break

            instr = self.extract_esil(cur_addr)
            self.addr_to_block[cur_addr] = (block, len(block.instrs))
            self.block_to_addr[(id(block), len(block.instrs))] = cur_addr
            block.instrs.append(instr)

            # check if ended by user action
            if cur_addr in self.end_addrs:
                break

            # check if we have a conditional jmp
            matches = re.match(r'(\d+),eip,=,(\wf),(!,)?\?{,(\d+),eip,=,}', instr)
            if matches:
                flag = matches.group(2)
                if not state.regs[flag].is_Integer:
                    is_negated = bool(matches.group(3))
                    constraint = ConstConstraint(state)
                    # explore remaining code first before exploring jmp
                    constraint.regs[flag] = sympify(int(not is_negated))
                    self.stack_append(int(matches.group(4)), constraint.to_state(self.names))
                    constraint.regs[flag] = sympify(int(is_negated))
                    self.stack_append(int(matches.group(4)), constraint.to_state(self.names))
                    block.condition = (flag, is_negated)
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
                        state.step_api_call(lib_name, api_name)
                        self.stack_append(int(ret_addr), state)
                        block.children = [int(ret_addr)]
                        break

            # check if instruction is a call to a proc
            # check if function was already analyzed

            state.step(instr)
            self.r.cmd('aes')

    def extract(self):
        self.stack_append(self.start_addr, self.constraint)
        self.r.cmd('aei')
        self.r.cmd('aeim')
        self.esp_0 = int(self.r.cmd(f'aer esp'), 16)
        while self.stack:
            self.extract_block(*self.stack.pop())
        addrs = {self.start_addr}
        for block, i in self.addr_to_block.values():
            addrs.update(block.children)
        func = Function(self.start_addr, {addr: self.addr_to_block[addr][0] for addr in addrs})
        constraint = None
        for end_addr in self.end_addrs:
            if not constraint:
                constraint = self.addr_to_constraint[end_addr]
            constraint.widen(self.addr_to_constraint[end_addr])
        self.funcs[self.start_addr] = func, constraint


class FuncsExtract:
    def __init__(self, r):
        self.r = r

    def extract_funcs(self, addr, constraint, end_addrs=()):
        funcs = {}
        FuncExtract(self.r, addr, funcs, constraint, end_addrs).extract()
        return sorted(funcs.values())
