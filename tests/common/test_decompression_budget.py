""" Tests for oletools.common.decompression_budget """

import io
import unittest

from oletools.common.decompression_budget import (
    DecompressionBudget, DecompressionLimitExceeded, LimitedReader,
    read_limited, DEFAULT_MAX_MEMBER_SIZE, DEFAULT_MAX_TOTAL_SIZE,
    CHUNK_SIZE)


class TestDecompressionBudget(unittest.TestCase):
    """ Tests the accounting/limit logic of DecompressionBudget """

    def test_defaults_are_large(self):
        """ default limits must stay far above normal office documents """
        budget = DecompressionBudget()
        self.assertEqual(budget.max_member_size, DEFAULT_MAX_MEMBER_SIZE)
        self.assertEqual(budget.max_total_size, DEFAULT_MAX_TOTAL_SIZE)
        self.assertGreaterEqual(DEFAULT_MAX_MEMBER_SIZE, 100 * 1024 * 1024)
        self.assertGreaterEqual(DEFAULT_MAX_TOTAL_SIZE, 1024 * 1024 * 1024)

    def test_charge_within_limits(self):
        """ ordinary accounting stays under the limits """
        budget = DecompressionBudget(max_member_size=10, max_total_size=20)
        budget.begin_member('a')
        budget.charge(5)
        budget.charge(5)
        self.assertEqual(budget.member_size, 10)
        self.assertEqual(budget.total_size, 10)

    def test_member_limit_exceeded(self):
        """ charging beyond the per-member limit raises a clear error """
        budget = DecompressionBudget(max_member_size=10, max_total_size=100)
        budget.begin_member('big')
        budget.charge(10)
        with self.assertRaises(DecompressionLimitExceeded) as caught:
            budget.charge(1)
        self.assertEqual(caught.exception.name, 'big')
        self.assertEqual(caught.exception.member_size, 11)
        # state must not be updated when the limit is hit
        self.assertEqual(budget.member_size, 10)
        self.assertEqual(budget.total_size, 10)
        self.assertIn('big', str(caught.exception))
        self.assertIn('per-member limit', str(caught.exception))

    def test_total_limit_exceeded(self):
        """ several small members can still exceed the total limit """
        budget = DecompressionBudget(max_member_size=100, max_total_size=15)
        budget.begin_member('a')
        budget.charge(10)
        budget.begin_member('b')
        budget.charge(5)
        with self.assertRaises(DecompressionLimitExceeded) as caught:
            budget.charge(1)
        self.assertEqual(caught.exception.name, 'b')
        self.assertIn('total limit', str(caught.exception))
        self.assertEqual(budget.total_size, 15)

    def test_declared_member_size_rejected_early(self):
        """ a member whose declared size is too big is rejected without
        producing any data """
        budget = DecompressionBudget(max_member_size=10, max_total_size=100)
        with self.assertRaises(DecompressionLimitExceeded):
            budget.begin_member('huge', declared_size=11)
        self.assertEqual(budget.total_size, 0)

    def test_declared_total_size_rejected_early(self):
        """ declared size is also checked against the remaining total budget """
        budget = DecompressionBudget(max_member_size=100, max_total_size=10)
        budget.begin_member('a', declared_size=6)
        budget.charge(6)
        with self.assertRaises(DecompressionLimitExceeded):
            budget.begin_member('c', declared_size=5)
        self.assertEqual(budget.total_size, 6)

    def test_discard_and_reread_not_double_counted(self):
        """ re-reading a member (seek/reset) must not count it twice """
        budget = DecompressionBudget(max_member_size=100, max_total_size=15)
        budget.begin_member('a')
        budget.charge(10)
        budget.discard_member()
        self.assertEqual(budget.total_size, 0)
        budget.begin_member('a')
        budget.charge(10)   # same bytes again, still within the total limit
        self.assertEqual(budget.total_size, 10)
        # without discarding, a second full read would breach the total limit
        budget.begin_member('b')
        budget.charge(5)
        with self.assertRaises(DecompressionLimitExceeded):
            budget.charge(1)

    def test_zero_means_unlimited(self):
        """ limits of 0 (set via callers, not the constructor) disable checks """
        budget = DecompressionBudget(max_member_size=None, max_total_size=None)
        budget.begin_member('a')
        for _ in range(1000):
            budget.charge(1024)
        self.assertEqual(budget.total_size, 1024 * 1000)

    def test_invalid_constructor_args(self):
        with self.assertRaises(ValueError):
            DecompressionBudget(max_member_size=-1)
        with self.assertRaises(ValueError):
            DecompressionBudget(max_total_size=-1)

    def test_declared_total_precheck(self):
        """ the sum of declared member sizes is checked up-front """
        budget = DecompressionBudget(max_member_size=1000,
                                     max_total_size=1000)
        budget.check_declared_total([400, 500])   # 900 fits
        with self.assertRaises(DecompressionLimitExceeded) as caught:
            budget.check_declared_total([400, 700])
        self.assertIn('declared total size', str(caught.exception))
        # pre-check never charges anything
        self.assertEqual(budget.total_size, 0)

    def test_declared_total_precheck_accounts_for_bytes_read(self):
        """ already-charged bytes reduce the remaining declared-total room """
        budget = DecompressionBudget(max_member_size=1000,
                                     max_total_size=1000)
        budget.begin_member('a')
        budget.charge(600)
        with self.assertRaises(DecompressionLimitExceeded):
            budget.check_declared_total([500])   # 600 + 500 > 1000

    def test_declared_total_precheck_disabled_when_unlimited(self):
        budget = DecompressionBudget(max_member_size=10, max_total_size=None)
        budget.check_declared_total([10 ** 9])   # must not raise


class TestLimitedReader(unittest.TestCase):
    """ Tests the file-like LimitedReader wrapper """

    def test_read_all_within_budget(self):
        data = b'x' * 100
        reader = LimitedReader(io.BytesIO(data),
                               DecompressionBudget(200, 500), 'm')
        self.assertEqual(reader.read(), data)
        self.assertEqual(reader.budget.total_size, 100)
        reader.close()
        self.assertTrue(reader.closed)

    def test_read_chunked_aborts_on_limit(self):
        """ no oversized chunk is ever returned to the caller """
        data = b'x' * 100
        reader = LimitedReader(io.BytesIO(data),
                               DecompressionBudget(10, 1000), 'm')
        with self.assertRaises(DecompressionLimitExceeded) as caught:
            while True:
                chunk = reader.read(16)
                if not chunk:
                    break
        self.assertEqual(caught.exception.name, 'm')

    def test_readline_charged(self):
        stream = io.BytesIO(b'line1\nline2\n')
        reader = LimitedReader(stream,
                               DecompressionBudget(100, 100), 'm')
        self.assertEqual(reader.readline(), b'line1\n')
        self.assertEqual(reader.readline(), b'line2\n')
        self.assertEqual(reader.readline(), b'')

    def test_read_on_closed_raises(self):
        reader = LimitedReader(io.BytesIO(b'x'),
                               DecompressionBudget(10, 10), 'm')
        reader.close()
        with self.assertRaises(IOError):
            reader.read()

    def test_context_manager(self):
        with LimitedReader(io.BytesIO(b'abc'),
                           DecompressionBudget(10, 10), 'm') as reader:
            self.assertEqual(reader.read(3), b'abc')
        self.assertTrue(reader.closed)

    def test_read_limited_helper_aborts_early(self):
        """ read_limited stops before assembling an oversized blob """
        data = b'z' * (CHUNK_SIZE * 3)
        budget = DecompressionBudget(max_member_size=CHUNK_SIZE,
                                     max_total_size=10 * CHUNK_SIZE)
        with self.assertRaises(DecompressionLimitExceeded):
            read_limited(io.BytesIO(data), budget, 'bomb')
        self.assertEqual(budget.total_size, CHUNK_SIZE)


if __name__ == '__main__':
    unittest.main()
