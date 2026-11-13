""" Tests for decompression limits in the olevba OOXML/ActiveMime chain

A malicious OOXML package can declare a small on-disk size while its zip
members (or a nested ActiveMime part) expand by orders of magnitude. These
tests check that such "bombs" are rejected with a clear error and that no
half-parsed macro result is produced, while ordinary files keep working.
"""

import io
import os
import struct
import sys
import unittest
import zlib
import zipfile
from tempfile import mkstemp

import olefile

from oletools import olevba
from oletools.olevba import (
    VBA_Parser, FileOpenError, MsoExtractionError, mso_file_extract,
    is_mso_file)
from oletools.common.decompression_budget import (
    DecompressionBudget, DecompressionLimitExceeded)
from tests.test_utils import call_and_capture


DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'test-data')


def _make_activemime(payload):
    """ wrap ``payload`` in a minimal ActiveMime/zlib container """
    compressed = zlib.compress(payload)
    start = 0x32
    blob = bytearray(start)
    blob[0:10] = b'ActiveMime'
    # header field at 0x1E plus 46 gives the compressed data offset
    struct.pack_into('<H', blob, 0x1E, start - 46)
    return bytes(blob) + compressed


class _TempFile(object):
    def __init__(self, data, suffix='.zip'):
        self.path = None
        self._data = data
        self._suffix = suffix

    def __enter__(self):
        handle, self.path = mkstemp(prefix='oletools-bomb-',
                                    suffix=self._suffix)
        os.close(handle)
        with open(self.path, 'wb') as writer:
            writer.write(self._data)
        return self.path

    def __exit__(self, *args, **kwargs):
        if self.path and os.path.isfile(self.path):
            os.unlink(self.path)


def _zip_with(members, compression=zipfile.ZIP_DEFLATED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression) as writer:
        for name, data in members:
            writer.writestr(name, data)
    return buffer.getvalue()


class TestMsoFileExtractLimits(unittest.TestCase):
    """ budget enforcement for nested ActiveMime parts """

    def setUp(self):
        self.small_blob = _make_activemime(b'x' * 1000)
        self.assertTrue(is_mso_file(self.small_blob))

    def test_without_budget_unchanged(self):
        """ no budget -> historical zlib.decompress behaviour """
        self.assertEqual(mso_file_extract(self.small_blob), b'x' * 1000)

    def test_budget_allows_normal_part(self):
        budget = DecompressionBudget(max_member_size=10000,
                                     max_total_size=10000)
        result = mso_file_extract(self.small_blob, budget=budget,
                                  name='editdata.mso')
        self.assertEqual(result, b'x' * 1000)
        self.assertEqual(budget.total_size, 1000)

    def test_budget_blocks_bomb(self):
        # 2 MiB of zeroes compress to a few KiB
        bomb = _make_activemime(b'\x00' * (2 * 1024 * 1024))
        budget = DecompressionBudget(max_member_size=64 * 1024,
                                     max_total_size=1024 * 1024)
        with self.assertRaises(DecompressionLimitExceeded) as caught:
            mso_file_extract(bomb, budget=budget, name='editdata.mso')
        self.assertEqual(caught.exception.name, 'editdata.mso')
        # failed extraction leaves no bytes charged behind
        self.assertEqual(budget.total_size, 0)

    def test_corrupt_mso_still_raises_mso_error(self):
        """ damaged parts keep raising MsoExtractionError, not a budget error
        (and the previously recursive constructor now works) """
        # cut the compressed stream short: no valid zlib end marker
        corrupt = self.small_blob[:0x32 + 2]
        with self.assertRaises(MsoExtractionError):
            mso_file_extract(corrupt,
                             budget=DecompressionBudget(10000, 10000))


class TestVbaParserOpenXmlLimits(unittest.TestCase):
    """ end-to-end budget enforcement for zip/OpenXML input """

    def test_bomb_member_rejected_with_clear_error(self):
        # a non-OLE member whose declared size already exceeds the limit:
        # VBA_Parser must fail loudly rather than silently scanning a bomb
        bomb_zip = _zip_with([('word/big.bin', b'\x00' * (2 * 1024 * 1024))])
        small_budget = DecompressionBudget(
            max_member_size=64 * 1024, max_total_size=1024 * 1024)
        with _TempFile(bomb_zip) as path:
            with self.assertRaises(FileOpenError) as caught:
                VBA_Parser(path, decompression_budget=small_budget)
            self.assertIsInstance(caught.exception.orig_exc,
                                  DecompressionLimitExceeded)
            self.assertIn('limit', str(caught.exception))

    def test_bomb_does_not_produce_partial_subfiles(self):
        """ even with an OLE magic at the start, an over-limit member aborts
        the whole parse and registers no sub-parser """
        ole_bytes = open(os.path.join(DATA_DIR, 'olevba',
                                      'sample_with_vba.ppt'), 'rb').read()
        # pad the OLE container with highly compressible data so the member
        # stays small on disk but expands beyond the limit
        padded_ole = ole_bytes + b'\x00' * (2 * 1024 * 1024)
        bomb_zip = _zip_with([('word/vbaProject.bin', padded_ole)])
        custom_budget = DecompressionBudget(
            max_member_size=64 * 1024, max_total_size=1024 * 1024)
        with _TempFile(bomb_zip) as path:
            parser = None
            try:
                parser = VBA_Parser(path, decompression_budget=custom_budget)
                self.fail('expected FileOpenError for over-limit member')
            except FileOpenError:
                pass
            # no partially built sub-parser and no OpenXML classification
            if parser is not None:
                self.assertEqual(parser.ole_subfiles, [])
                self.assertIsNone(parser.type)
            self.assertEqual(custom_budget.total_size, 0)

    def test_budget_shared_with_embedded_subparser(self):
        """ the same budget object is handed down to nested sub-parsers """
        parent = VBA_Parser.__new__(VBA_Parser)
        parent.relaxed = True
        parent.encoding = None
        parent.disable_pcode = False
        shared = DecompressionBudget(1234, 9999)
        parent.decompression_budget = shared
        parent.ole_subfiles = []
        parent.append_subfile('inner.bin', b'not an ole file')
        self.assertEqual(len(parent.ole_subfiles), 1)
        self.assertIs(parent.ole_subfiles[0].decompression_budget, shared)

    def test_declared_total_rejected_for_peek_only_members(self):
        """ members that are not OLE are only peeked at, but the declared
        total of the archive is still enforced before reading starts """
        bomb_zip = _zip_with(
            [('part{0}.bin'.format(i), b'x' * 4096) for i in range(8)])
        small_budget = DecompressionBudget(
            max_member_size=100 * 1024, max_total_size=10 * 1024)
        with _TempFile(bomb_zip) as path:
            with self.assertRaises(FileOpenError) as caught:
                VBA_Parser(path, decompression_budget=small_budget)
            self.assertIsInstance(caught.exception.orig_exc,
                                  DecompressionLimitExceeded)
            self.assertIn('total', str(caught.exception).lower())

    def test_normal_openxml_still_parses(self):
        """ a real macro-enabled document is unaffected by the default limits
        and still reports the same type """
        sample = os.path.join(DATA_DIR, 'oleform', 'oleform-PR314.docm')
        parser = VBA_Parser(sample)
        try:
            self.assertEqual(parser.type, olevba.TYPE_OpenXML)
            self.assertTrue(parser.detect_vba_macros())
        finally:
            parser.close()


class TestWord2003XmlActiveMimeLimit(unittest.TestCase):
    """ a bomb inside a Word2003-XML binData part is rejected """

    def test_open_word2003xml_bomb(self):
        import binascii
        bomb = _make_activemime(b'\x00' * (2 * 1024 * 1024))
        encoded = binascii.b2a_base64(bomb)
        xml = (b'<?xml version="1.0"?>'
               b'<w:wordDocument xmlns:w="http://schemas.microsoft.com/'
               b'office/word/2003/wordml"><w:body><w:binData w:name="x.mso">'
               + encoded + b'</w:binData></w:body></w:wordDocument>')
        parser = VBA_Parser.__new__(VBA_Parser)
        parser.filename = '<word2003 bomb>'
        parser.relaxed = True
        parser.decompression_budget = DecompressionBudget(
            max_member_size=64 * 1024, max_total_size=1024 * 1024)
        with self.assertRaises(FileOpenError) as caught:
            parser.open_word2003xml(xml)
        self.assertIsInstance(caught.exception.orig_exc,
                              DecompressionLimitExceeded)


class TestOlevbaCliLimit(unittest.TestCase):
    """ the old command line keeps working but reports bombs explicitly """

    def test_cli_rejects_bomb_with_open_error_code(self):
        # member declared above the default per-member limit, tiny on disk
        bomb_zip = _zip_with(
            [('word/vbaProject.bin',
              b'\x00' * (200 * 1024 * 1024))])
        with _TempFile(bomb_zip, suffix='.docm') as path:
            output, ret_code = call_and_capture(
                'olevba', args=(path, ), accept_nonzero_exit=True)
        self.assertEqual(ret_code, olevba.RETURN_OPEN_ERROR)
        self.assertIn('Decompression limit exceeded', output)
        self.assertIn('per-member limit', output)
        # no half-produced macro output
        self.assertNotIn('VBA MACRO', output)
        self.assertNotIn('Attribute VB_Name', output)

    def test_cli_still_handles_normal_docm(self):
        sample = os.path.join(DATA_DIR, 'oleform', 'oleform-PR314.docm')
        output, ret_code = call_and_capture('olevba', args=(sample, ))
        self.assertEqual(ret_code, olevba.RETURN_OK)
        self.assertIn('Type: OpenXML', output)


if __name__ == '__main__':
    unittest.main()
