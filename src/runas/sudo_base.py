#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  esky.sudo.sudo_base:  base functionality for esky sudo helpers

"""


import sys
import base64
import struct

try:
    import cPickle as pickle
except ImportError:
    import pickle


def b64pickle(obj):
    """Serialize object to a base64-string."""
    return base64.b64encode(pickle.dumps(obj, -1)).decode("ascii")


def b64unpickle(data):
    """Deserialize object from a base64-string."""
    if sys.version_info[0] > 2:
        data = data.encode("ascii")
    return pickle.loads(base64.b64decode(data))


def has_root():
    """Check whether the user currently has root access."""
    return False


def can_get_root():
    """Check whether the user may be able to get root access.

    This is currently always True on unix-like platforms, since we have no
    way of peering inside the sudoers file.
    """
    return True


class StringPipe:
    def __init__(self):
        self.connected = False

    def __del__(self):
        self.close()

    def _read(self, size):
        raise NotImplementedError

    def _write(self, data):
        raise NotImplementedError

    def close(self):
        self.connected = False

    def read(self):
        """Read the next string from the pipe.

        The expected data format is:  4-byte size, data, signature
        """
        sz = self._read(4)
        if len(sz) < 4:
            raise EOFError()
        sz = struct.unpack("I", sz)[0]
        data = self._read(sz)
        if len(data) < sz:
            raise EOFError()
        return data

    def write(self, data):
        """Write the given string to the pipe.

        The expected data format is:  4-byte size, data, signature
        """
        self._write(struct.pack("I", len(data)))
        self._write(data)


def spawn_sudo(proxy):
    """Spawn the sudo slave process, returning proc and a pipe to message it."""
    raise NotImplementedError


def run_startup_hooks():
    raise NotImplementedError
