from expects import *

from analysis.block import (
    esil_to_sa, sa_expr_simp, sa_include_flag_deps, sa_include_subword_deps, sa_mem_elim, sa_to_ssa, ssa_to_sa
)
from analysis.specs._stub import *

with description('esil_to_sa'):
    with it('converts constants'):
        expect(esil_to_sa([
            '1,eax,=',
            '0x1,eax,=',
            '$0,$z,=',
            '$1,$z,=',
        ])).to(equal([
            ('eax', '=', 1),
            ('eax', '=', 1),
            ('$z', '=', 0),
            ('$z', '=', 1),
        ]))

    with it('converts memory writes'):
        expect(esil_to_sa([
            '1,eax,=[]',
            '1,eax,=[1]',
            '1,eax,=[2]',
            '1,eax,=[4]',
        ])).to(equal([
            ('eax', '[4]=', 1),
            ('eax', '[1]=', 1),
            ('eax', '[2]=', 1),
            ('eax', '[4]=', 1),
        ]))

    with it('converts memory reads'):
        expect(esil_to_sa([
            'eax,[1]',
            'eax,[2]',
            'eax,[4]',
        ])).to(equal([
            ('tmp_0', '=[1]', 'eax'),
            ('tmp_1', '=[2]', 'eax'),
            ('tmp_2', '=[4]', 'eax'),
        ]))

    with it('converts operations'):
        expect(esil_to_sa([
            'ebx,eax,+',
        ])).to(equal([
            ('tmp_0', '=', '+', 'eax', 'ebx'),
        ]))

    with it('converts operation assign'):
        expect(esil_to_sa([
            '1,eax,+=',
        ])).to(equal([
            ('eax', '=', '+', 'eax', 1),
        ]))

    with it('converts multiple stacked operations'):
        expect(esil_to_sa([
            'edx,ecx,+,ebx,eax,-,*',
        ])).to(equal([
            ('tmp_0', '=', '+', 'ecx', 'edx'),
            ('tmp_1', '=', '-', 'eax', 'ebx'),
            ('tmp_2', '=', '*', 'tmp_1', 'tmp_0'),
        ]))

    with it('raises error for unknown opcodes'):
        expect(lambda: esil_to_sa(['unknown'])).to(raise_error(ValueError))

with description('sa_include_flag_deps'):
    with it('converts flags'):
        expect(sa_include_flag_deps([
            ('eax', '[4]=', '+', 'eax', 'ebx'),
            ('of', '=', '$o'),
            ('sf', '=', '$s'),
            ('zf', '=', '$z'),
            ('cf', '=', '$c31'),
            ('pf', '=', '$p'),
        ])).to(equal([
            ('tmp', '=', '+', 'eax', 'ebx'),
            ('eax', '[4]=', 'tmp'),
            ('of', '=', '$o', 'tmp'),
            ('sf', '=', '$s', 'tmp'),
            ('zf', '=', '$z', 'tmp'),
            ('cf', '=', '$c31', 'tmp'),
            ('pf', '=', '$p', 'tmp'),
        ]))

    with it('does not modify non-flag instructions'):
        expect(sa_include_flag_deps([
            ('eax', '=', 'eax', 'ebx'),
        ])).to(equal([
            ('eax', '=', 'eax', 'ebx'),
        ]))

with description('sa_include_subword_deps'):
    with it('updates on subword writes'):
        expect(sa_include_subword_deps([
            ('al', '=', '1'),
        ])).to(equal([
            ('al', '=', '1'),
            ('eax', 'l=', 'al'),
        ]))

    with it('updates on subword accesses'):
        expect(sa_include_subword_deps([
            ('ebx', '[2]=', 'al'),
        ])).to(equal([
            ('al', '=l', 'eax'),
            ('ebx', '[2]=', 'al'),
        ]))

with description('sa_to_ssa'):
    with it('changes to ssa form'):
        expect(sa_to_ssa([
            ('eax', '=', '+', 'eax', 'ecx'),
            ('ebx', '=', 'eax'),
            ('eax', '=', 'ebx'),
        ])).to(equal([
            ('eax_1', '=', '+', 'eax_0', 'ecx_0'),
            ('ebx_1', '=', 'eax_1'),
            ('eax_2', '=', 'ebx_1'),
        ]))

    with it('works with subwords'):
        expect(sa_to_ssa([
            ('al', 'x=', 'eax'),
        ])).to(equal([
            ('al_1', 'x=', 'eax_0'),
        ]))

    with it('recounts all names'):
        expect(sa_to_ssa([
            ('tmp_3', '=', 'tmp_2'),
            ('tmp', '=', 'tmp_3'),
        ])).to(equal([
            ('tmp_1', '=', 'tmp_0'),
            ('tmp_2', '=', 'tmp_1'),
        ]))

with description('ssa_to_sa'):
    with it('recounts & remove counters from initial & final registers'):
        expect(ssa_to_sa([
            ('eax_2', '=', '+', 'eax_1', 'ecx_1'),
            ('ebx_1', '[]=', 'eax_2'),
            ('ebx_2', '=', 'eax_2'),
            ('eax_3', '=', 'ebx_2'),
        ])).to(equal([
            ('eax_1', '=', '+', 'eax', 'ecx'),
            ('ebx', '[]=', 'eax_1'),
            ('ebx', '=', 'eax_1'),
            ('eax', '=', 'ebx'),
        ]))

with description('sa_expr_simp'):
    with it('simplifies xor same register to 0'):
        expect(sa_expr_simp([
            ('r2', '=', '^', 'r1', 'r1'),
        ])).to(equal([
            ('r2', '=', 0),
        ]))

    with it('simplifies xor expressions'):
        expect(sa_expr_simp([
            ('r3', '=', '^', 'r1', 'r2'),
            ('r4', '=', '^', 'r3', 'r1'),
        ])).to(equal([
            ('r3', '=', '^', 'r1', 'r2'),
            ('r4', '=', 'r2'),
        ]))

    with it('simplifies additions'):
        expect(sa_expr_simp([
            ('r2', '=', '+', 'r1', 1),
            ('r3', '=', '+', 'r2', 1),
            ('r4', '=', '-', 'r3', 3),
            ('r5', '=', '+', 'r4', 1),
        ])).to(equal([
            ('r2', '=', '+', 'r1', 1),
            ('r3', '=', '+', 'r1', 2),
            ('r4', '=', '-', 'r1', 1),
            ('r5', '=', 'r1'),
        ]))

with description('sa_mem_elim'):
    with context('read'):
        with it('simplifies for constant addresses'):
            expect(sa_mem_elim([
                (0, '[4]=', 1),
                (4, '[4]=', 2),
                ('r1', '=[4]', 0),
                ('r2', '=[4]', 4),
            ])).to(equal([
                (0, '[4]=', 1),
                (4, '[4]=', 2),
                ('r1', '=', 1),
                ('r2', '=', 2),
            ]))

        with it('simplifies for register + constant'):
            expect(sa_mem_elim([
                ('s2', '=', '+', 's1', 4),
                ('s3', '=', '-', 's1', 4),
                ('s1', '[4]=', 1),
                ('s2', '[4]=', 2),
                ('s3', '[4]=', 3),
                ('r1', '=[4]', 's1'),
                ('r2', '=[4]', 's2'),
                ('r3', '=[4]', 's3'),
            ])).to(equal([
                ('s2', '=', '+', 's1', 4),
                ('s3', '=', '-', 's1', 4),
                ('s1', '[4]=', 1),
                ('s2', '[4]=', 2),
                ('s3', '[4]=', 3),
                ('r1', '=', 1),
                ('r2', '=', 2),
                ('r3', '=', 3),
            ]))

        with it('simplifies re-reads even for overlaps'):
            expect(sa_mem_elim([
                ('r1', '=[4]', 0),
                ('r2', '=[4]', 2),
                ('r3', '=[4]', 0),
                ('r4', '=[4]', 2),
            ])).to(equal([
                ('r1', '=[4]', 0),
                ('r2', '=[4]', 2),
                ('r3', '=', 'r1'),
                ('r4', '=', 'r2'),
            ]))

        with it('simplifies re-reads after write (regression)'):
            expect(sa_mem_elim([
                ('s1', '[4]=', 0),
                ('r1', '=[4]', 0),
                ('r2', '=[4]', 0),
            ])).to(equal([
                ('s1', '[4]=', 0),
                ('r1', '=[4]', 0),
                ('r2', '=', 'r1'),
            ]))

        with it('does not simplify for write in-between with overlap'):
            expect(sa_mem_elim([
                (0, '[4]=', 1),
                (2, '[4]=', 2),
                ('r1', '=[4]', 0),
            ])).to(equal([
                (0, '[4]=', 1),
                (2, '[4]=', 2),
                ('r1', '=[4]', 0),
            ]))

        with it('does not simplify for write in-between with unknown register'):
            expect(sa_mem_elim([
                (0, '[4]=', 1),
                ('s1', '[4]=', 2),
                ('r1', '=[4]', 0),
            ])).to(equal([
                (0, '[4]=', 1),
                ('s1', '[4]=', 2),
                ('r1', '=[4]', 0),
            ]))

    with context('write'):
        with it('removes redundant write even if unrelated value is read in-between'):
            # redundant write if unrelated value is read in-between
            expect(sa_mem_elim([
                (0, '[4]=', 1),
                ('r1', '=[4]', 4),
                (0, '[4]=', 2),
            ])).to(equal([
                ('r1', '=[4]', 4),
                (0, '[4]=', 2),
            ]))

        with it('preserves write if overlapped value is read in-between'):
            expect(sa_mem_elim([
                (0, '[4]=', 1),
                ('r1', '=[4]', 2),
                (0, '[4]=', 2),
            ])).to(equal([
                (0, '[4]=', 1),
                ('r1', '=[4]', 2),
                (0, '[4]=', 2),
            ]))

        with it('preserves write if unknown memory is read in-between'):
            expect((sa_mem_elim([
                (0, '[4]=', 1),
                ('r1', '=[4]', 's1'),
                (0, '[4]=', 2),
            ]))).to(equal([
                (0, '[4]=', 1),
                ('r1', '=[4]', 's1'),
                (0, '[4]=', 2),
            ]))
