
__all__ = ['update_radare_state']


def eval_cons_val(val, initial_vars):
    return val if isinstance(val, int) else initial_vars[val[0]] + val[1]


def update_radare_state(r, con, initial_vars):
    '''
    For emulating decrypting routines once such a routine is identified through static analysis.
    '''
    initial_vars = {f'{key}_0': val for key, val in initial_vars.items()}
    con = con.const_cons[0]
    for name, val in con.vars.items():
        r.cmd(f'aer {name}={eval_cons_val(val, initial_vars)}')
    for (offset, size), val in con.stack.values.items():
        r.cmd(f'ae {eval_cons_val(val, initial_vars)},{initial_vars["esp_0"] + offset},=[{size}]')
    mem_base = con.mem_var and initial_vars[con.mem_var]
    for (offset, size), val in con.mem.values.items():
        r.cmd(f'ae {eval_cons_val(val, initial_vars)},{mem_base + offset},=[{size}]')
