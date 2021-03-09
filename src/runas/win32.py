#  All rights reserved; available under the terms of the MIT License.
"""
win32 platform-specific functionality for runas
"""
import os
import sys
import ctypes
import ctypes.wintypes
import subprocess
import win32security
import win32con
import pickle
import logging
from . import base

logger = logging.getLogger("runas")

byref = ctypes.byref
sizeof = ctypes.sizeof
kernel32 = ctypes.windll.kernel32
shell32 = ctypes.windll.shell32
advapi32 = ctypes.windll.advapi32

GENERIC_READ = -0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_RDWR = GENERIC_READ | GENERIC_WRITE
OPEN_EXISTING = 3
TOKEN_QUERY = 8
SECURITY_MAX_SID_SIZE = 68
SECURITY_SQOS_PRESENT = 1048576
SECURITY_IDENTIFICATION = 65536
WinBuiltinAdministratorsSid = 26
ERROR_NO_SUCH_LOGON_SESSION = 1312
ERROR_PRIVILEGE_NOT_HELD = 1314
TokenLinkedToken = 19
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100


def _errcheck_bool(value, func, args):
    if not value:
        raise ctypes.WinError()
    return args


try:
    OpenProcessToken = advapi32.OpenProcessToken
except AttributeError:
    pass
else:
    OpenProcessToken.restype = ctypes.wintypes.BOOL
    OpenProcessToken.errcheck = _errcheck_bool
    OpenProcessToken.argtypes = (
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.wintypes.HANDLE)
    )

try:
    CreateWellKnownSid = advapi32.CreateWellKnownSid
except AttributeError:
    pass
else:
    CreateWellKnownSid.restype = ctypes.wintypes.BOOL
    CreateWellKnownSid.errcheck = _errcheck_bool
    CreateWellKnownSid.argtypes = (
        ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.wintypes.DWORD),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.wintypes.DWORD)
    )

try:
    CheckTokenMembership = advapi32.CheckTokenMembership
except AttributeError:
    pass
else:
    CheckTokenMembership.restype = ctypes.wintypes.BOOL
    CheckTokenMembership.errcheck = _errcheck_bool
    CheckTokenMembership.argtypes = (
        ctypes.wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.wintypes.BOOL)
    )

try:
    GetTokenInformation = advapi32.GetTokenInformation
except AttributeError:
    pass
else:
    GetTokenInformation.restype = ctypes.wintypes.BOOL
    GetTokenInformation.errcheck = _errcheck_bool
    GetTokenInformation.argtypes = (
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.wintypes.DWORD)
    )


def has_root():
    """Check whether the user currently has root access."""
    return bool(shell32.IsUserAnAdmin())


def can_get_root():
    """Check whether the user may be able to get root access."""
    #  On Vista or higher, there's the whole UAC token-splitting thing.
    #  Many thanks for Junfeng Zhang for the workflow:
    #      http://blogs.msdn.com/junfeng/archive/2007/01/26/how-to-tell-if-the-current-user-is-in-administrators-group-programmatically.aspx
    proc = kernel32.GetCurrentProcess()
    #  Get the token for the current process.
    try:
        token = ctypes.wintypes.HANDLE()
        OpenProcessToken(proc, TOKEN_QUERY, byref(token))
        try:
            #  Get the administrators SID.
            sid = ctypes.create_string_buffer(SECURITY_MAX_SID_SIZE)
            sz = ctypes.wintypes.DWORD(SECURITY_MAX_SID_SIZE)
            target_sid = WinBuiltinAdministratorsSid
            CreateWellKnownSid(target_sid, None, byref(sid), byref(sz))
            #  Check whether the token has that SID directly.
            has_admin = ctypes.wintypes.BOOL()
            CheckTokenMembership(None, byref(sid), byref(has_admin))
            if has_admin.value:
                return True
            #  Get the linked token.  Failure may mean no linked token.
            lToken = ctypes.wintypes.HANDLE()
            try:
                cls = TokenLinkedToken
                GetTokenInformation(token, cls, byref(lToken), sizeof(lToken), byref(sz))
            except WindowsError as e:
                if e.winerror == ERROR_NO_SUCH_LOGON_SESSION:
                    return False
                elif e.winerror == ERROR_PRIVILEGE_NOT_HELD:
                    return False
                else:
                    raise
            #  Check if the linked token has the admin SID
            try:
                CheckTokenMembership(lToken, byref(sid), byref(has_admin))
                return bool(has_admin.value)
            finally:
                kernel32.CloseHandle(lToken)
        finally:
            kernel32.CloseHandle(token)
    finally:
        kernel32.CloseHandle(proc)


def spawn_sudo(proxy, user, password, domain):
    """Spawn the sudo slave process, returning proc and a pipe to message it.

    This function spawns the proxy app with administrator privileges, using
    ShellExecuteEx and the undocumented-but-widely-recommended "runas" verb.
    """
    exe = [sys.executable, "-c", "import runas; runas.run_proxy_startup()"]
    args = ["--runas-spawn-sudo", base.b64pickle(sys.path), base.b64pickle(proxy)]
    exe = exe + args
    nul = subprocess.DEVNULL
    pipe = subprocess.PIPE
    kwds = dict(stdin=pipe, stdout=pipe, stderr=nul, close_fds=True, text=False)
    logger.debug("start subprocess %r", exe)
    proc = subprocess.Popen(exe, **kwds)
    proc.stdin.write(pickle.dumps((user, domain, password)))
    proc.stdin.flush()
    return proc, base.StdPipe(proc.stdout, proc.stdin)


def run_proxy_startup():
    if len(sys.argv) > 1 and sys.argv[1] == "--runas-spawn-sudo":
        sys.path = base.b64unpickle(sys.argv[2])
        proxy = base.b64unpickle(sys.argv[3])
        pipe = base.StdPipe(os.fdopen(sys.stdin.fileno(), "rb"),
                            os.fdopen(sys.stdout.fileno(), "wb"))

        user, domain, password = pickle.load(pipe)
        handle = win32security.LogonUser(
            user, domain, password, win32con.LOGON32_LOGON_INTERACTIVE,
            win32con.LOGON32_PROVIDER_DEFAULT)
        win32security.ImpersonateLoggedOnUser(handle)
        proxy.run(pipe)
        win32security.RevertToSelf()
        handle.close()
        sys.exit(0)
