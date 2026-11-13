""" Tests for decompression limits in the OOXML (zip) reading chain

All malicious fixtures are generated in temporary files: a small zip on disk
expands to far more data once a member is decompressed ("zip bomb").
"""

import io
import os
import unittest
import zipfile
from tempfile import mkstemp

from oletools import ooxml
from oletools.common.decompression_budget import (
    DecompressionLimitExceeded, DecompressionBudget)
from oletools.ooxml import XmlParser, ZipSubFile


def _write_zip(path, members):
    """ write a zip with the given (name, data) members to ``path`` """
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as writer:
        for name, data in members:
            writer.writestr(name, data)


class _TempZip(object):
    """ context manager creating and cleaning up a temporary zip file """

    def __init__(self, members):
        self.path = None
        self._members = members

    def __enter__(self):
        handle, self.path = mkstemp(prefix='oletools-bomb-', suffix='.zip')
        os.close(handle)
        _write_zip(self.path, self._members)
        return self.path

    def __exit__(self, *args, **kwargs):
        if self.path and os.path.isfile(self.path):
            os.unlink(self.path)


class TestXmlParserLimits(unittest.TestCase):
    """ per-member and total limits enforced through XmlParser """

    def test_small_member_declared_over_limit_rejected(self):
        """ a member whose declared uncompressed size exceeds the per-member
        limit is rejected before decompression starts """
        payload = b'a' * 4096
        with _TempZip([('word/document.xml', payload)]) as path:
            parser = XmlParser(path, max_member_size=1024)
            with self.assertRaises(DecompressionLimitExceeded) as caught:
                list(parser.iter_files())
            self.assertEqual(caught.exception.name, 'word/document.xml')
            self.assertGreaterEqual(caught.exception.member_size, 4096)

    def test_actual_decompression_aborts(self):
        """ highly compressible data is stopped while being read even if the
        zip header itself looks small """
        # 1 MiB of zeroes compresses to ~1 KiB on disk
        payload = b'\x00' * (1024 * 1024)
        with _TempZip([('big.bin', payload)]) as path:
            on_disk = os.path.getsize(path)
            self.assertLess(on_disk, 10 * 1024)   # tiny file on disk
            parser = XmlParser(path, max_member_size=64 * 1024)
            with self.assertRaises(DecompressionLimitExceeded):
                # consume every yielded handle like a real caller would
                for _, handle in parser.iter_files():
                    while handle.read(65536):
                        pass

    def test_total_limit_across_members(self):
        """ several members below the per-member limit still trip the total """
        members = [('m{0}.bin'.format(i), b'x' * 4096) for i in range(8)]
        with _TempZip(members) as path:
            parser = XmlParser(path, max_member_size=10 * 1024,
                               max_total_size=10 * 1024)
            with self.assertRaises(DecompressionLimitExceeded) as caught:
                for _, handle in parser.iter_files():
                    while handle.read(4096):
                        pass
            self.assertIn('total limit', str(caught.exception))

    def test_declared_total_rejected_even_without_reading(self):
        """ a package whose members only get peeked at still trips the total
        because the declared sizes are checked before any read """
        members = [('m{0}.bin'.format(i), b'x' * 4096) for i in range(8)]
        with _TempZip(members) as path:
            parser = XmlParser(path, max_member_size=100 * 1024,
                               max_total_size=10 * 1024)
            with self.assertRaises(DecompressionLimitExceeded) as caught:
                # open every member but never read more than a few bytes
                for _, handle in parser.iter_files():
                    handle.read(4)
            self.assertIn('total', str(caught.exception).lower())

    def test_normal_small_zip_unaffected(self):
        """ ordinary members remain readable with small custom limits """
        members = [('a.xml', b'<a/>'), ('b.xml', b'<b/>')]
        with _TempZip(members) as path:
            parser = XmlParser(path, max_member_size=1024,
                               max_total_size=4096)
            read_back = dict()
            for name, handle in parser.iter_files():
                read_back[name] = handle.read()
            self.assertEqual(read_back, dict(members))

    def test_iter_xml_limit_does_not_yield_partial_data(self):
        """ a bomb in xml parsing raises the explicit error instead of
        returning partial elements """
        payload = b'<root>' + (b'a' * 8192) + b'</root>'
        with _TempZip([('x.xml', payload)]) as path:
            parser = XmlParser(path, max_member_size=1024)
            with self.assertRaises(DecompressionLimitExceeded):
                list(parser.iter_xml())


class TestZipSubFileLimits(unittest.TestCase):
    """ limits enforced by the ZipSubFile used for non-xml/OLE members """

    def test_constructor_rejects_declared_oversize(self):
        payload = b'q' * 2048
        with _TempZip([('ole.bin', payload)]) as path:
            with zipfile.ZipFile(path) as zipper:
                budget = DecompressionBudget(max_member_size=1024,
                                             max_total_size=10000)
                with self.assertRaises(DecompressionLimitExceeded):
                    ZipSubFile(zipper, 'ole.bin', budget=budget)

    def test_read_aborts_and_reset_stays_counted_once(self):
        """ read() raises on limit; a reset re-reads without double counting
        the same bytes against the total budget """
        payload = b'z' * 4096
        with _TempZip([('ole.bin', payload)]) as path:
            with zipfile.ZipFile(path) as zipper:
                budget = DecompressionBudget(max_member_size=10000,
                                             max_total_size=10000)
                with ZipSubFile(zipper, 'ole.bin', budget=budget) as handle:
                    self.assertEqual(handle.read(100), b'z' * 100)
                    handle.reset()
                    self.assertEqual(handle.read(100), b'z' * 100)
                    self.assertEqual(budget.total_size, 100)

    def test_no_budget_keeps_legacy_behaviour(self):
        """ ZipSubFile without a budget behaves exactly as before """
        payload = b'legacy' * 100
        with _TempZip([('old.bin', payload)]) as path:
            with zipfile.ZipFile(path) as zipper:
                with ZipSubFile(zipper, 'old.bin') as handle:
                    self.assertEqual(handle.read(), payload)


class TestInMemoryZip(unittest.TestCase):
    """ limits also apply when the zip is passed as a file-like object """

    def test_bomb_in_bytesio(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as writer:
            writer.writestr('bomb.bin', b'\x00' * (512 * 1024))
        buffer.seek(0)
        parser = XmlParser(buffer, max_member_size=64 * 1024)
        with self.assertRaises(DecompressionLimitExceeded):
            for _, handle in parser.iter_files():
                while handle.read(65536):
                    pass


if __name__ == '__main__':
    unittest.main()
