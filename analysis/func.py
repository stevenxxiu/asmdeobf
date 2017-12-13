from analysis.block import Block

__all__ = ['Function', 'ESILToFunc', 'func_simplify']


class Function:
    def __init__(self, addr, block):
        self.addr = addr
        self.block = block

    @property
    def blocks(self):
        # dfs to be more natural for unit tests (matches esil order)
        visited = set()
        stack = [self.block]
        while stack:
            block = stack.pop()
            if id(block) not in visited:
                yield block
                visited.add(id(block))
                stack.extend(reversed(block.children))


class ESILToFunc:
    def __init__(self, instr, addr, size):
        self.instr = instr
        self.addr = addr
        self.size = size
        self.instr_stack = []
        self.stack_zeros = []  # [i], for gotos and branches, assumes they are always have stack 0
        self.block_stack = []  # [block], for branches
        self.gotos = []  # [(block, i)], for gotos
        self.i_to_block_i = {}  # {i: (block, block_i)}, records all points we can jmp to, for gotos

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
        return Block(addr_sizes=[(self.addr, self.size)])

    def _append_instr(self, instr, block):
        if len(self.instr_stack) == 0:
            self.i_to_block_i[self.stack_zeros[-1]] = (block, len(block.instrs))
        block.instrs.append(instr)

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
                self.stack_zeros.append(i)
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
                self._append_instr((self.instr_stack.pop(), part, self.instr_stack.pop()), block)
            elif part in ('!',):
                src = self.instr_stack.pop()
                self._append_instr((f'tmp_{tmp_num}', '=', part, src), block)
                self.instr_stack.append(f'tmp_{tmp_num}')
                tmp_num += 1
            elif part in ('++=', '--='):
                src = self.instr_stack.pop()
                self._append_instr((src, '=', part[:-1], src), block)
            elif part in ('&=', '|=', '^=', '+=', '-=', '*=', '/='):
                dest = self.instr_stack.pop()
                src = self.instr_stack.pop()
                self._append_instr((dest, '=', part[:-1], dest, src), block)
            elif part in ('&', '|', '^', '+', '-', '==', '*', '/'):
                src_1 = self.instr_stack.pop()
                src_2 = self.instr_stack.pop()
                self._append_instr((f'tmp_{tmp_num}', '=', part, src_1, src_2), block)
                self.instr_stack.append(f'tmp_{tmp_num}')
                tmp_num += 1
            elif part in ('[1]', '[2]', '[4]'):
                # read from memory
                self._append_instr((f'tmp_{tmp_num}', f'={part}', self.instr_stack.pop()), block)
                self.instr_stack.append(f'tmp_{tmp_num}')
                tmp_num += 1
            elif part.startswith('=['):
                # write to memory
                dest = self.instr_stack.pop()
                src = self.instr_stack.pop()
                size = part[2:-1] or '4'
                self._append_instr((dest, f'[{size}]=', src), block)
            elif part == '?{':
                block.condition = self.instr_stack.pop()
                block.children = (self._new_block(), self._new_block())
                self.block_stack.append(block.children[1])
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
                block = block.children[0]
            elif part == '}':
                block.children = (self.block_stack.pop(),)
                block = block.children[0]
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
            elif part == 'SKIP':
                self.gotos.append((block, i + self.instr_stack.pop() + 1))
                block = self._new_block()
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
            elif part == 'GOTO':
                self.gotos.append((block, self.instr_stack.pop()))
                block = self._new_block()
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
            elif part == 'LOOP':
                self.gotos.append((block, 0))
                block = self._new_block()
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
            elif part == 'BREAK':
                self.gotos.append((block, len(parts)))
                block = self._new_block()
                if len(self.instr_stack) != 0:
                    raise ValueError('stack is not 0')
            else:
                raise ValueError('instr', part)
        if len(self.instr_stack) != 0:
            raise ValueError('stack is not 0')
        end_block = block

        # process gotos
        for block, i in self.gotos:
            if i == len(parts) and i not in self.i_to_block_i:
                # create new empty block
                end_block.children = (self._new_block(),)
                end_block = end_block.children[0]
                self.i_to_block_i[i] = end_block, 0
            if i not in self.i_to_block_i:
                raise ValueError('stack is not 0')
            goto_block, block_i = self.i_to_block_i[i]
            if block_i != 0:
                upper_half = goto_block.split(block_i)
                if start_block == goto_block:
                    start_block = upper_half
            block.children = (goto_block,)

        # instr transforms
        func = Function(self.addr, start_block)
        for block in func.blocks:
            block.instrs = self._sa_include_flag_deps(block.instrs)
            block.instrs = self._sa_include_subword_deps(block.instrs)
        return func, end_block


def func_remove_same_children(func):
    # XXX test
    for block_addr, block in func.blocks.items():
        if len(block.children) == 2 and block.children[0] == block.children[1]:
            child = func.blocks[block.children[0]]
            child.instrs = block.instrs + child.instrs
            func.blocks[block_addr] = child


def func_simplify(func):
    # XXX test
    func_remove_same_children(func)
