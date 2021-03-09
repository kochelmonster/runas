#  All rights reserved; available under the terms of the MIT License.
"""
posix specific functionality
"""
import os
import sys
import subprocess
import logging
from . import base

logger = logging.getLogger("runas")


def has_root():
    """Check whether the use current has root access."""
    return os.geteuid() == 0


def can_get_root():
    """Check whether the user may be able to get root access.

    This is currently always True on unix-like platforms, since we have no
    sensible way of peering inside the sudoers file.
    """
    return True


def find_exe(name, *args):
    path = os.environ.get("PATH", "/bin:/usr/bin").split(":")
    if getattr(sys, "frozen", False):
        path.append(os.path.dirname(sys.executable))
    for dir in path:
        exe = os.path.join(dir, name)
        if os.path.exists(exe):
            return [exe] + list(args)
    return None


def spawn_sudo(proxy, user, password, domain):
    """Spawn the sudo slave process, returning proc and a pipe to message it."""
    exe = [sys.executable, "-c", "import runas; runas.run_proxy_startup()"]
    args = ["--runas-spawn-sudo", base.b64pickle(sys.path), base.b64pickle(proxy)]
    # Look for a variety of sudo-like programs
    sudo = find_exe("sudo")
    if sudo is None:
        raise RuntimeError("no sudo found")

    # Make it a slave process so it dies if we die
    sudo.append("-p")
    sudo.append("")
    sudo.append("-k")
    sudo.append("-u")
    sudo.append(user)
    sudo.append("-S")
    exe = sudo + exe + args
    # Pass the pipe in environment vars, they seem to be harder to snoop.

    # Spawn the subprocess
    pipe = subprocess.PIPE
    kwds = dict(stdin=pipe, stdout=pipe, stderr=pipe, close_fds=True, text=False)
    # kwds = dict(stdin=pipe, stdout=pipe, close_fds=True, text=False)
    logger.debug("start subprocess %r", exe)
    proc = subprocess.Popen(exe, **kwds)
    proc.stdin.write(password.encode("utf8")+b"\n")
    proc.stdin.flush()

    result = proc.stderr.read(1)
    proc.stderr.close()
    if result != b"@":
        proc.stdin.close()
        proc.stdout.close()
        proc.kill()
        raise RuntimeError("wrong password")

    return proc, base.StdPipe(proc.stdout, proc.stdin)


def run_proxy_startup():
    logger.debug("run_proxy_startup %r", sys.argv)
    sys.stderr.write("@")
    sys.stderr.flush()
    if len(sys.argv) > 1 and sys.argv[1] == "--runas-spawn-sudo":
        sys.path = base.b64unpickle(sys.argv[2])
        proxy = base.b64unpickle(sys.argv[3])
        proxy.run(base.StdPipe(os.fdopen(sys.stdin.fileno(), "rb"),
                               os.fdopen(sys.stdout.fileno(), "wb")))
        sys.exit(0)
