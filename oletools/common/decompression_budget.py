#!/usr/bin/env python3

"""
Unified budgets for data decompressed from OOXML (ZIP) members and nested
MSO/ActiveMime containers.

Zip-based office formats (docx, xlsx, pptm, ...) as well as ActiveMime parts
store compressed data: a small on-disk file can expand by orders of
magnitude (a "decompression bomb"). Reading every member without a limit can
therefore exhaust memory while scanning, even though the declared/on-disk
size of the package looks harmless.

This module provides:

* :class:`DecompressionLimitExceeded`: a clear, specific error raised when a
  configured limit is exceeded
* :class:`DecompressionBudget`: tracks both the per-member and the total
  amount of decompressed data produced while reading one container
* :class:`LimitedReader`: a file-like wrapper that enforces a budget while
  streaming from another reader (e.g. a ``zipfile`` member or a zlib stream)

The default limits are deliberately high enough that every real-world office
document stays well below them, so normal files and the existing command line
behaviour remain unchanged. Limits can be overridden via the constructor
arguments for tests or special deployments.

License: BSD, see source code or documentation
"""

# -- CONSTANTS ---------------------------------------------------------------

#: Default maximum size of a single decompressed member/part (100 MiB)
DEFAULT_MAX_MEMBER_SIZE = 100 * 1024 * 1024

#: Default maximum total size of all decompressed data per container (1 GiB)
DEFAULT_MAX_TOTAL_SIZE = 1024 * 1024 * 1024

#: Chunk size used when fully draining a reader through the budget
CHUNK_SIZE = 64 * 1024


# -- EXCEPTION ---------------------------------------------------------------


class DecompressionLimitExceeded(IOError):
    """Raised when decompressed data exceeds the configured budget.

    Subclasses :class:`IOError` so that callers which already handle
    ``IOError`` around file/stream reading keep working, while the specific
    type allows detecting an over-limit package explicitly.

    Attributes:
        name: name of the offending member/part (may be ``None``)
        member_size: decompressed bytes produced for this member so far
        total_size: decompressed bytes produced through the whole budget
        member_limit: configured per-member limit
        total_limit: configured total limit
    """

    def __init__(self, message, name=None, member_size=None, total_size=None,
                 member_limit=None, total_limit=None):
        super(DecompressionLimitExceeded, self).__init__(message)
        self.name = name
        self.member_size = member_size
        self.total_size = total_size
        self.member_limit = member_limit
        self.total_limit = total_limit


# -- BUDGET ------------------------------------------------------------------


class DecompressionBudget(object):
    """Track decompressed bytes produced while reading one container.

    Two limits are enforced independently:

    * ``max_member_size``: maximum amount of decompressed data a single
      member/part may produce
    * ``max_total_size``: maximum amount of decompressed data all members of
      the container together may produce

    A member is opened with :meth:`begin_member` (which also rejects members
      whose *declared* size already exceeds the per-member limit, avoiding
      even starting the decompression) and every produced chunk is accounted
      for with :meth:`charge`. :meth:`discard_member` gives back the bytes of
      a member when its stream is re-read from the start (e.g. a seek back),
      so re-reading a legitimate member never triggers a false positive.
    """

    def __init__(self, max_member_size=DEFAULT_MAX_MEMBER_SIZE,
                 max_total_size=DEFAULT_MAX_TOTAL_SIZE):
        if max_member_size is not None and max_member_size < 0:
            raise ValueError('max_member_size must be non-negative or None')
        if max_total_size is not None and max_total_size < 0:
            raise ValueError('max_total_size must be non-negative or None')
        self.max_member_size = max_member_size
        self.max_total_size = max_total_size
        self._total = 0
        self._member = None
        self._member_size = 0

    @property
    def total_size(self):
        """Total decompressed bytes accounted for so far."""
        return self._total

    @property
    def member_name(self):
        """Name of the currently open member (or ``None``)."""
        return self._member

    @property
    def member_size(self):
        """Decompressed bytes accounted for the current member so far."""
        return self._member_size

    def begin_member(self, name=None, declared_size=None):
        """Start accounting for a new member/part.

        :param name: name of the member (used in error messages)
        :param declared_size: size the container claims the decompressed
            member will have. If it already exceeds the per-member limit the
            member is rejected before any decompression starts.
        :raises DecompressionLimitExceeded: if the declared per-member size or
            the remaining total budget is insufficient.
        """
        if declared_size is not None:
            if (self.max_member_size is not None and
                    declared_size > self.max_member_size):
                self._raise_member(name, declared_size, self._total,
                                   declared=declared_size)
            if (self.max_total_size is not None and
                    self._total + declared_size > self.max_total_size):
                self._raise_total(name, declared_size,
                                  self._total + declared_size)
        self._member = name
        self._member_size = 0

    def check_declared_total(self, declared_sizes, name=None):
        """Reject a container whose members' declared sizes already exceed the
        total budget, without charging any of them.

        Useful when members are not all read in full (e.g. only the magic of
        each zip entry is inspected): the attacker cannot hide an oversized
        total behind members that are merely peeked at.

        :param declared_sizes: iterable of the uncompressed sizes the
            container declares for its members
        :param name: name of the container, used in error messages
        :raises DecompressionLimitExceeded: if the sum exceeds ``max_total_size``
        """
        if self.max_total_size is None:
            return
        declared_total = sum(declared_sizes)
        if self._total + declared_total > self.max_total_size:
            raise DecompressionLimitExceeded(
                'Decompression limit exceeded{0}: declared total size {1} '
                'bytes (plus {2} bytes already read) exceeds total limit of '
                '{3} bytes'
                .format(' for container ' + _format_name(name)
                        if name is not None else '',
                        declared_total, self._total, self.max_total_size),
                name=name, member_size=0,
                total_size=self._total + declared_total,
                member_limit=self.max_member_size,
                total_limit=self.max_total_size)

    def charge(self, amount):
        """Account for ``amount`` newly decompressed bytes.

        :raises DecompressionLimitExceeded: if the per-member or total limit
            would be exceeded. No state is updated in that case, so the
            caller can close the stream without ending up with half-counted
            data.
        """
        if not amount:
            return
        new_member_size = self._member_size + amount
        new_total = self._total + amount
        if (self.max_member_size is not None and
                new_member_size > self.max_member_size):
            self._raise_member(self._member, new_member_size, new_total)
        if (self.max_total_size is not None and
                new_total > self.max_total_size):
            self._raise_total(self._member, new_member_size, new_total)
        self._member_size = new_member_size
        self._total = new_total

    def discard_member(self):
        """Return the current member's bytes to the total budget.

        Needed when a member stream is reset and re-read from the beginning:
        the bytes already produced will be produced again, so they must not be
        counted twice.
        """
        self._total -= self._member_size
        if self._total < 0:
            self._total = 0
        self._member_size = 0

    def _raise_member(self, name, member_size, total_size, declared=None):
        what = 'declared size' if declared is not None else 'decompressed size'
        raise DecompressionLimitExceeded(
            'Decompression limit exceeded for member {0}: {1} {2} bytes '
            'exceeds per-member limit of {3} bytes'
            .format(_format_name(name), what, member_size,
                    self.max_member_size),
            name=name, member_size=member_size, total_size=total_size,
            member_limit=self.max_member_size,
            total_limit=self.max_total_size)

    def _raise_total(self, name, member_size, total_size):
        location = (' while reading member ' + _format_name(name)
                    if name is not None else '')
        raise DecompressionLimitExceeded(
            'Decompression limit exceeded{0}: total decompressed size {1} '
            'bytes exceeds total limit of {2} bytes'
            .format(location, total_size, self.max_total_size),
            name=name, member_size=member_size, total_size=total_size,
            member_limit=self.max_member_size,
            total_limit=self.max_total_size)


def _format_name(name):
    return repr(name) if name is not None else '<unknown>'


# -- LIMITED READER ----------------------------------------------------------


class LimitedReader(object):
    """File-like wrapper enforcing a :class:`DecompressionBudget`.

    Every byte read from the wrapped reader is charged against the given
    budget before being handed to the caller. When a limit is exceeded,
    :class:`DecompressionLimitExceeded` is raised and no partial chunk is
    returned: the caller only sees the explicit error.

    The wrapper supports the subset of the file-like interface needed by
    ``zipfile`` consumers, ``lxml``/``ElementTree`` parsers and
    :func:`olefile.OleFileIO`: ``read``, ``readline``, ``close``, context
    manager and the ``readable``/``writable``/``seekable`` introspection
    methods. Seeking is intentionally not supported (the underlying zip/zlib
    streams are not seekable either); use a fresh wrapper after resetting the
    underlying stream.
    """

    def __init__(self, reader, budget, name=None, begin=True):
        """Wrap ``reader`` and enforce ``budget``.

        When ``begin`` is true (the default), a new member called ``name`` is
        opened on the budget immediately, including the declared-size checks.
        Callers which have already invoked :meth:`DecompressionBudget.begin_member`
        themselves pass ``begin=False`` to keep the existing member accounting.
        """
        self.reader = reader
        self.budget = budget
        self.name = name
        self.closed = False
        if begin:
            budget.begin_member(name)

    def readable(self):
        return True

    def writable(self):
        return False

    def seekable(self):
        return False

    def read(self, size=-1):
        """Read up to ``size`` bytes, enforcing the budget."""
        if self.closed:
            raise IOError('read on closed handle')
        data = self.reader.read(size)
        if data:
            self.budget.charge(len(data))
        return data

    def readline(self, size=-1):
        if self.closed:
            raise IOError('read on closed handle')
        line = self.reader.readline(size)
        if line:
            self.budget.charge(len(line))
        return line

    def close(self):
        if not self.closed and self.reader is not None:
            try:
                self.reader.close()
            finally:
                self.closed = True

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    # Python 2 spelling of the iterator protocol
    next = __next__

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.close()


def read_limited(reader, budget, name=None):
    """Read all data from ``reader`` under ``budget`` and return it.

    Streaming helper for code paths that need the full content in memory
    (e.g. an OLE subfile handed to ``olefile``). Data is pulled in chunks so
    that an over-limit member aborts the read before a huge blob is ever
    assembled; on limit error nothing is returned to the caller.
    """
    limited = LimitedReader(reader, budget, name)
    parts = []
    try:
        while True:
            chunk = limited.read(CHUNK_SIZE)
            if not chunk:
                break
            parts.append(chunk)
        return b''.join(parts)
    finally:
        limited.close()
