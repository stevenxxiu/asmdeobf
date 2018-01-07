from analysis.block import Block

__all__ = ['Function', 'ESILToFunc', 'func_simplify']


class Function:
    def __init__(self, addr, block):
        self.addr = addr
        self.block = block


class ESILToFunc:
    def __init__(self, instr, addr, size):
        self.instr = instr
        self.addr = addr
        self.size = size
        self.instr_stack = []
        self.block_stack = []  # [block], for branches
        self.gotos = []  # [(block_goto_is_at_end_of, i)], for gotos
        self.labels = {}  # {i: (block, block_i)}, records all points we can jmp to, for gotos

    @staticmethod
    def _sa_include_flag_deps(instrs):
        '''
        Include all register dependencies for flags.
        '''
        instrs_new = instrs[:1]
        for prev_instr, instr in zip(instrs[:-1], instrs[1:]):
            if isinstance(instr[2], str) and instr[2].startswith('$'):
                if not (isinstance(prev_instr[2], str) and prev_instr[2].startswith('$')):
                    instrs_new.pop()
                    instrs_new.append(('tmp', '=') + prev_instr[2:])
                    instrs_new.append(prev_instr[:2] + ('tmp',))
                instr = instr + ('tmp',)
            instrs_new.append(instr)
        return instrs_new

    @staticmethod
    def _sa_include_subword_deps(instrs):
        '''
        Include all register dependencies for sub-word modifications, generated redundant code is optimized later.
        '''
        regdefs = [
            ('al', 'eax', 'l'), ('ah', 'eax', 'h'), ('ax', 'eax', 'x'),
            ('cl', 'ecx', 'l'), ('ch', 'ecx', 'h'), ('cx', 'ecx', 'x'),
            ('dl', 'edx', 'l'), ('dh', 'edx', 'h'), ('dx', 'edx', 'x'),
            ('bl', 'ebx', 'l'), ('bh', 'ebx', 'h'), ('bx', 'ebx', 'x'),
            ('sp', 'esp', 'x'),
            ('bp', 'ebp', 'x'),
            ('si', 'esi', 'x'),
            ('di', 'edi', 'x'),
        ]
        instrs_new = []
        for instr in instrs:
            for subreg, reg, op in regdefs:
                if subreg in instr[2:]:
                    instrs_new.append((subreg, f'={op}', reg))
            instrs_new.append(instr)
            for subreg, reg, op in regdefs:
                if subreg == instr[0]:
                    instrs_new.append((reg, f'{op}=', subreg))
        return instrs_new

    def _new_block(self):
        return Block(addr_sizes={(self.addr, self.size)})

    def convert(self):
        '''
        Assumes stack is 0 before and after any branch, as temp variables are not preserved across block boundaries.
        :return: Function and block that the next instruction will continue from.
        '''
        tmp_num = 0
        start_block = self._new_block()

        # convert to cfg minus gotos
        block = start_block
        parts = self.instr.split(',')
        for i, part in enumerate(parts):
            if len(self.instr_stack) == 0:
                self.labels[i] = (block, len(block.instrs))  # cannot be in middle of instruction when 0
            if str.isdecimal(part):
                self.instr_stack.append(int(part))
            elif part.startswith('0x'):
                self.instr_stack.append(int(part, 16))
            elif part == '$0':
                self.instr_stack.append(0)
            elif part == '$1':
                self.instr_stack.append(1)
            elif part.startswith('$'):
                # esil register
                self.instr_stack.append(part)
            elif part in (
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
                # x86 register
                self.instr_stack.append(part)
            elif part == '=':
                block.instrs.append((self.instr_stack.pop(), part, self.instr_stack.pop()))
            elif part in ('!',):
                src = self.instr_stack.pop()
                block.instrs.append((f'tmp_{tmp_num}', '=', part, src))
                self.instr_stack.append(f'tmp_{tmp_num}')
                tmp_num += 1
            elif part == '++=':
                src = self.instr_stack.pop()
                block.instrs.append((src, '=', '+', src, 1))
            elif part == '--=':
                src = self.instr_stack.pop()
                block.instrs.append((src, '=', '-', src, 1))
            elif part == '==':
                src_1 = self.instr_stack.pop()
                src_2 = self.instr_stack.pop()
                block.instrs.append((f'tmp_{tmp_num}', '=', part, src_1, src_2))
                tmp_num += 1
            elif part in ('&=', '|=', '^=', '+=', '-=', '*=', '/='):
                dest = self.instr_stack.pop()
                src = self.instr_stack.pop()
                block.instrs.append((dest, '=', part[:-1], dest, src))
            elif part in ('&', '|', '^', '+', '-', '*', '/'):
                src_1 = self.instr_stack.pop()
                src_2 = self.instr_stack.pop()
                block.instrs.append((f'tmp_{tmp_num}', '=', part, src_1, src_2))
                self.instr_stack.append(f'tmp_{tmp_num}')
                tmp_num += 1
            elif part in ('[]', '[1]', '[2]', '[4]'):
                # read from memory
                size = part[1:-1] or '4'
                block.instrs.append((f'tmp_{tmp_num}', f'=[{size}]', self.instr_stack.pop()))
                self.instr_stack.append(f'tmp_{tmp_num}')
                tmp_num += 1
            elif part.startswith('=['):
                # write to memory
                dest = self.instr_stack.pop()
                src = self.instr_stack.pop()
                size = part[2:-1] or '4'
                block.instrs.append((dest, f'[{size}]=', src))
            elif part == '?{':
                block.condition = self.instr_stack.pop()
                block.children = (self._new_block(), self._new_block())
                self.block_stack.append(block.children[1])
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
                block = block.children[0]
            elif part == '}':
                block.children = (self.block_stack.pop(),)
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
                block = block.children[0]
            elif part == 'SKIP':
                self.gotos.append((block, i + self.instr_stack.pop() + 1))
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
                block = self._new_block()
            elif part == 'GOTO':
                self.gotos.append((block, self.instr_stack.pop()))
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
                block = self._new_block()
            elif part == 'LOOP':
                self.gotos.append((block, 0))
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
                block = self._new_block()
            elif part == 'BREAK':
                self.gotos.append((block, len(parts)))
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
                block = self._new_block()
            else:
                raise ValueError('instr', part)
        if len(self.instr_stack) != 0:
            raise ValueError('stack is not 0')
        end_block = block

        # process gotos
        for block, i in self.gotos:
            if i == len(parts) and i not in self.labels:
                # create new empty block
                end_block.children = (self._new_block(),)
                end_block = end_block.children[0]
                self.labels[i] = end_block, 0
            if i not in self.labels:
                raise ValueError('stack is not 0')
            goto_block, block_i = self.labels[i]
            if block_i != 0:
                goto_block.children = (goto_block.split(block_i),)
                if block is goto_block:
                    block = goto_block.children[0]
                goto_block = goto_block.children[0]
            block.children = (goto_block,)

        # instr transforms
        func = Function(self.addr, start_block)
        for block in func.block.dfs():
            block.instrs = self._sa_include_flag_deps(block.instrs)
            block.instrs = self._sa_include_subword_deps(block.instrs)
        return func


def func_merge_single_children(func):
    for block in func.block.dfs():
        while len(block.children) == 1 and not block.call:
            block.merge(block.children[0])


def func_remove_same_children(func):
    for block in func.block.dfs():
        if len(block.children) == 2:
            child_1, child_2 = block.children
            if (
                child_1.instrs == child_2.instrs and child_1.children == child_2.children and
                child_1.condition == child_2.condition
            ):
                child_1.addr_sizes.update(child_2.addr_sizes)
                block.merge(child_1)


def func_simplify(func):
    func_merge_single_children(func)
    func_remove_same_children(func)
