#  All rights reserved; available under the terms of the BSD License.
"""
runas.sudo_unix:  unix platform-specific functionality for esky.sudo
"""
import os
import sys
import errno
import subprocess
import tempfile
from . import sudo_base as base


def has_root():
    """Check whether the use current has root access."""
    return os.geteuid() == 0


def can_get_root():
    """Check whether the user may be able to get root access.

    This is currently always True on unix-like platforms, since we have no
    sensible way of peering inside the sudoers file.
    """
    return True


class SecureStringPipe(base.SecureStringPipe):
    """A two-way pipe for securely communicating with a sudo subprocess.

    On unix this is implemented as a pair of fifos.  It would be more secure
    to use anonymous pipes, but they're not reliably inherited through sudo
    wrappers such as gksudo.

    Unfortunately this leaves the pipes wide open to hijacking by other
    processes running as the same user.  Security depends on secrecy of the
    message-hashing token, which we pass to the slave in its env vars.
    """

    def __init__(self, token=None, data=None):
        super().__init__(token)
        self.rfd = None
        self.wfd = None
        if data is None:
            self.tdir = tempfile.mkdtemp()
            self.rnm = os.path.join(self.tdir, "master")
            self.wnm = os.path.join(self.tdir, "slave")
            os.mkfifo(self.rnm, 0o600)
            os.mkfifo(self.wnm, 0o600)
        else:
            self.tdir, self.rnm, self.wnm = data

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def connect(self):
        return SecureStringPipe(self.token, (self.tdir, self.wnm, self.rnm))

    def _read(self, size):
        return os.read(self.rfd, size)

    def _write(self, data):
        return os.write(self.wfd, data)

    def _open(self):
        if self.rnm.endswith("master"):
            self.rfd = os.open(self.rnm, os.O_RDONLY)
            self.wfd = os.open(self.wnm, os.O_WRONLY)
        else:
            self.wfd = os.open(self.wnm, os.O_WRONLY)
            self.rfd = os.open(self.rnm, os.O_RDONLY)
        os.unlink(self.wnm)

    def _recover(self):
        try:
            os.close(os.open(self.rnm, os.O_WRONLY))
        except EnvironmentError:
            pass
        try:
            os.close(os.open(self.wnm, os.O_RDONLY))
        except EnvironmentError:
            pass

    def close(self):
        if self.rfd is not None:
            os.close(self.rfd)
            os.close(self.wfd)
            self.rfd = None
            self.wfd = None
            if os.path.isfile(self.wnm):
                os.unlink(self.wnm)
            try:
                if not os.listdir(self.tdir):
                    os.rmdir(self.tdir)
            except EnvironmentError as e:
                if e.errno != errno.ENOENT:
                    raise
        super().close()


def find_exe(name, *args):
    path = os.environ.get("PATH", "/bin:/usr/bin").split(":")
    if getattr(sys, "frozen", False):
        path.append(os.path.dirname(sys.executable))
    for dir in path:
        exe = os.path.join(dir, name)
        if os.path.exists(exe):
            return [exe] + list(args)
    return None


def spawn_sudo(proxy):
    """Spawn the sudo slave process, returning proc and a pipe to message it."""
    nul = subprocess.DEVNULL
    pipe = SecureStringPipe()
    c_pipe = pipe.connect()
    exe = [sys.executable, "-c", "import runas; runas.run_proxy_startup()"]
    args = ["--runas-spawn-sudo", base.b64pickle(sys.path), base.b64pickle(proxy),
            base.b64pickle(c_pipe)]
    # Look for a variety of sudo-like programs
    sudo = None
    if "DISPLAY" in os.environ:
        sudo = find_exe("pkexec")
        if sudo is None:
            sudo = find_exe("gksudo", "-k", "-D", proxy.display_name, "--")
        if sudo is None:
            sudo = find_exe("kdesudo")
        if sudo is None:
            sudo = find_exe("cocoasudo", f"--prompt='{proxy.display_name}'")
    if sudo is None:
        sudo = find_exe("sudo")
    if sudo is None:
        sudo = []
    # Make it a slave process so it dies if we die
    exe = sudo + exe + args
    # Pass the pipe in environment vars, they seem to be harder to snoop.
    env = os.environ.copy()
    # Spawn the subprocess
    # kwds = dict(stdin=nul, stdout=nul, stderr=nul, close_fds=True, env=env)
    kwds = dict(stdin=nul, close_fds=True, env=env)
    proc = subprocess.Popen(exe, **kwds)
    return (proc, pipe)


def run_proxy_startup():
    if len(sys.argv) > 1 and sys.argv[1] == "--runas-spawn-sudo":
        sys.path = base.b64unpickle(sys.argv[2])
        proxy = base.b64unpickle(sys.argv[3])
        pipe = base.b64unpickle(sys.argv[4])
        proxy.run(pipe)
        sys.exit(0)
