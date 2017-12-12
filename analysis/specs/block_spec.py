from expects import *

from analysis.block import sa_expr_simp, sa_mem_elim, sa_to_ssa, ssa_to_sa
from analysis.specs._stub import *

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
    with description('read'):
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

    with description('write'):
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
