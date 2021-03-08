#  All rights reserved; available under the terms of the BSD License.
"""
runas.sudo_osx:  unix platform-specific functionality for esky.sudo
"""
import os
import sys
import errno
import subprocess
import tempfile
from shlex import quote
from . import sudo_base as base
from .sudo_unix import has_root, can_get_root, SecureStringPipe, run_proxy_startup


if sys.platform != "darwin":
    raise ImportError("only usable on OSX")


def quote_shell(args):
    return " ".join(quote(arg) for arg in args)


def quote_applescript(string):
    charmap = {
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
        "\"": "\\\"",
        "\\": "\\\\",
    }
    return '"' + "".join(charmap.get(char, char) for char in string) + '"'


def spawn_sudo(proxy):
    """Spawn the sudo slave process, returning proc and a pipe to message it."""

    nul = subprocess.DEVNULL
    pipe = SecureStringPipe()
    c_pipe = pipe.connect()
    exe = [sys.executable, "-c", "'import runas; runas.run_proxy_startup()'"]
    exe += ["--runas-spawn-sudo", base.b64pickle(sys.path), base.b64pickle(proxy),
            base.b64pickle(c_pipe)]

    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as callscript:
        callscript.write(" ".join(exe))

    args = ["sh", callscript.name]
    call_args = [
        "osascript",
        "-e",
        "do shell script {script} "
        "with prompt \"{msg}\""
        "with administrator privileges "
        "without altering line endings".format(
            script=quote_applescript(quote_shell(args)),
            msg=str(proxy.display_name))]

    # Pass the pipe in environment vars, they seem to be harder to snoop.
    env = os.environ.copy()
    # Spawn the subprocess
    kwds = dict(stdin=nul, stdout=nul, stderr=nul, close_fds=True, env=env)
    proc = subprocess.Popen(call_args, **kwds)
    return (proc, pipe)
