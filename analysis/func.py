
__all__ = ['simplify_func']


def func_remove_empty(func):
    for block_addr, block in func.blocks.items():
        for i, child_addr in enumerate(block.children):
            child = func.blocks[child_addr]
            if not [instr for instr in child.instrs if '?{' not in instr] and len(child.children) == 1:
                block.children[i] = child.children[0]


def func_remove_same_children(func):
    for block_addr, block in func.blocks.items():
        if len(block.children) == 2 and block.children[0] == block.children[1]:
            child = func.blocks[block.children[0]]
            child.instrs = block.instrs + child.instrs
            func.blocks[block_addr] = child


def func_dead_code_elim(func):
    addrs = {func.addr}
    stack = [func.addr]
    while stack:
        children = func.blocks[stack.pop()].children
        addrs.update(children)
        stack.extend(children)
    func.blocks = {addr: func.blocks[addr] for addr in addrs}


def simplify_func(func):
    func_remove_empty(func)
    func_remove_same_children(func)
    func_dead_code_elim(func)
