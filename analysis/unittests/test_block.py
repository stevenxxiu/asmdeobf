import unittest

from analysis.block import sa_expr_simp, sa_mem_elim


class TestSAExprSimp(unittest.TestCase):
    def test_simplify_xor(self):
        self.assertEqual(sa_expr_simp([
            ('r2', '=', '^', 'r1', 'r1'),
        ]), [
            ('r2', '=', 0),
        ])
        self.assertEqual(sa_expr_simp([
            ('r3', '=', '^', 'r1', 'r2'),
            ('r4', '=', '^', 'r3', 'r1'),
        ]), [
            ('r3', '=', '^', 'r1', 'r2'),
            ('r4', '=', 'r2'),
        ])


class TestSAMemElim(unittest.TestCase):
    def test_simplify_read(self):
        # address
        self.assertEqual(sa_mem_elim([
            (0, '[4]=', 1),
            (4, '[4]=', 2),
            ('r1', '=[4]', 0),
            ('r2', '=[4]', 4),
        ]), [
            (0, '[4]=', 1),
            (4, '[4]=', 2),
            ('r1', '=', 1),
            ('r2', '=', 2),
        ])

        # register
        self.assertEqual(sa_mem_elim([
            ('s2', '=', '+', 's1', 4),
            ('s3', '=', '-', 's1', 4),
            ('s1', '[4]=', 1),
            ('s2', '[4]=', 2),
            ('s3', '[4]=', 3),
            ('r1', '=[4]', 's1'),
            ('r2', '=[4]', 's2'),
            ('r3', '=[4]', 's3'),
        ]), [
            ('s2', '=', '+', 's1', 4),
            ('s3', '=', '-', 's1', 4),
            ('s1', '[4]=', 1),
            ('s2', '[4]=', 2),
            ('s3', '[4]=', 3),
            ('r1', '=', 1),
            ('r2', '=', 2),
            ('r3', '=', 3),
        ])

        # re-read works even with overlaps
        self.assertEqual(sa_mem_elim([
            ('r1', '=[4]', 0),
            ('r2', '=[4]', 2),
            ('r3', '=[4]', 0),
            ('r4', '=[4]', 2),
        ]), [
            ('r1', '=[4]', 0),
            ('r2', '=[4]', 2),
            ('r3', '=', 'r1'),
            ('r4', '=', 'r2'),
        ])

        # re-read works after write
        self.assertEqual(sa_mem_elim([
            ('s1', '[4]=', 0),
            ('r1', '=[4]', 0),
            ('r2', '=[4]', 0),
        ]), [
            ('s1', '[4]=', 0),
            ('r1', '=[4]', 0),
            ('r2', '=', 'r1'),
        ])

        # write in-between with overlap
        self.assertEqual(sa_mem_elim([
            (0, '[4]=', 1),
            (2, '[4]=', 2),
            ('r1', '=[4]', 0),
        ]), [
            (0, '[4]=', 1),
            (2, '[4]=', 2),
            ('r1', '=[4]', 0),
        ])

        # write in-between with unknown register
        self.assertEqual(sa_mem_elim([
            (0, '[4]=', 1),
            ('s1', '[4]=', 2),
            ('r1', '=[4]', 0),
        ]), [
            (0, '[4]=', 1),
            ('s1', '[4]=', 2),
            ('r1', '=[4]', 0),
        ])

    def test_simplify_write(self):
        # redundant write if unrelated value is read in-between
        self.assertEqual(sa_mem_elim([
            (0, '[4]=', 1),
            ('r1', '=[4]', 4),
            (0, '[4]=', 2),
        ]), [
            ('r1', '=[4]', 4),
            (0, '[4]=', 2),
        ])

        # write is not redundant if overlapped value is read in-between
        self.assertEqual(sa_mem_elim([
            (0, '[4]=', 1),
            ('r1', '=[4]', 2),
            (0, '[4]=', 2),
        ]), [
            (0, '[4]=', 1),
            ('r1', '=[4]', 2),
            (0, '[4]=', 2),
        ])

        # write is not redundant if register is read in-between
        self.assertEqual(sa_mem_elim([
            (0, '[4]=', 1),
            ('r1', '=[4]', 's1'),
            (0, '[4]=', 2),
        ]), [
            (0, '[4]=', 1),
            ('r1', '=[4]', 's1'),
            (0, '[4]=', 2),
        ])
