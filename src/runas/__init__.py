#  Copyright (c) 2009-2010, Cloud Matrix Pty. Ltd.
#  All rights reserved; available under the terms of the BSD License.
"""

  sudo:  spawn a root-privileged helper app to process updates.

This module provides the infrastructure for spawning a stand-alone "helper app"
to install updates with root privileges.  The class "SudoProxy" provides a
proxy to the methods of an object via a root-privileged helper process.

Example:

    app.install_version("1.2.3")
    -->   IOError:  permission denied

    sapp = SudoProxy(app)
    sapp.start()
    -->   prompts for credentials
    sapp.install_version("1.2.3")
    -->   success!


We also provide some handy utility functions:

    * has_root():      check whether current process has root privileges
    * can_get_root():  check whether current process may be able to get root
"""

from __future__ import absolute_import

import sys
import functools
import pickle


if sys.platform == "win32":
    from . import sudo_win32 as sudo
else:
    from . import sudo_posix as sudo


def spawn_sudo(proxy, user, password):
    return sudo.spawn_sudo(proxy, user, password)


def has_root():
    return sudo.has_root()


def can_get_root():
    return sudo.can_get_root()


def run_proxy_startup():
    return sudo.run_proxy_startup()


class SudoProxy:
    """Object method proxy with root privileges.

    This class creates a copy of an object whose methods can be executed
    with root privileges.
    """

    def __init__(self, target):
        #  Reflect the 'name' attribute if it has one, but don't worry
        #  if not.  This helps SudoProxy be re-used on other classes.
        self.target = target
        self.closed = False
        self.pipe = None

    def start(self, user, password):
        (self.proc, self.pipe) = spawn_sudo(self, user, password)
        if self.proc.poll() is not None:
            raise RuntimeError("sudo helper process terminated unexpectedly")
        #  Try to read initialisation message from the pipe.
        #  If this fails, the helper program must have died.
        try:
            msg = self.pipe.read()
        except EOFError:
            msg = b""
        if msg != b"READY":
            self.close()
            raise RuntimeError("failed to spawn helper app")

    def close(self):
        self.pipe.write(pickle.dumps("CLOSE"))
        self.pipe.read()
        self.closed = True

    def terminate(self):
        if not self.closed:
            self.close()
        self.pipe.close()
        self.pipe = None
        self.proc.wait()

    def run(self, pipe):
        self.target.sudo_proxy = self
        pipe.write(b"READY")
        try:
            #  Process incoming commands in a loop.
            while True:
                try:
                    call = pickle.loads(pipe.read())
                    if call == "CLOSE":
                        pipe.write(pickle.dumps("CLOSING"))
                        break
                    else:
                        methname, args = call
                        try:
                            method = getattr(self.target, methname)
                            res = method(*args)
                        except Exception as e:
                            pipe.write(pickle.dumps((False, e)))
                        else:
                            pipe.write(pickle.dumps((True, res)))
                except EOFError:
                    break
        finally:
            pipe.close()

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError(attr)

        target = self.__dict__["target"]
        method = getattr(target, attr)
        pipe = self.__dict__["pipe"]

        @functools.wraps(method)
        def wrapper(*args):
            call = (method.__name__, args)
            pipe.write(pickle.dumps(call))
            (success, result) = pickle.loads(pipe.read())
            if not success:
                raise result
            return result

        setattr(self, attr, wrapper)
        return wrapper
