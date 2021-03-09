#  All rights reserved; available under the terms of the MIT License.
"""
win32 platform-specific functionality for runas
"""
import sys
import uuid
import ctypes
import ctypes.wintypes
import subprocess
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


class SHELLEXECUTEINFO(ctypes.Structure):
    _fields_ = (
      ("cbSize", ctypes.wintypes.DWORD),
      ("fMask", ctypes.c_ulong),
      ("hwnd", ctypes.wintypes.HANDLE),
      ("lpVerb", ctypes.c_char_p),
      ("lpFile", ctypes.c_char_p),
      ("lpParameters", ctypes.c_char_p),
      ("lpDirectory", ctypes.c_char_p),
      ("nShow", ctypes.c_int),
      ("hInstApp", ctypes.wintypes.HINSTANCE),
      ("lpIDList", ctypes.c_void_p),
      ("lpClass", ctypes.c_char_p),
      ("hKeyClass", ctypes.wintypes.HKEY),
      ("dwHotKey", ctypes.wintypes.DWORD),
      ("hIconOrMonitor", ctypes.wintypes.HANDLE),
      ("hProcess", ctypes.wintypes.HANDLE),
    )


try:
    ShellExecuteEx = shell32.ShellExecuteEx
except AttributeError:
    ShellExecuteEx = None
else:
    ShellExecuteEx.restype = ctypes.wintypes.BOOL
    ShellExecuteEx.errcheck = _errcheck_bool
    ShellExecuteEx.argtypes = (
        ctypes.POINTER(SHELLEXECUTEINFO),
    )


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


class Win32Pipe(base.StdPipe):
    def __init__(self, pipename=None):
        if pipename is None:
            self.pipename = r"\\.\pipe\runas-" + uuid.uuid4().hex
            self.pipename = self.pipename.encode('utf8')
            self.pipe = kernel32.CreateNamedPipeA(self.pipename, 0x03, 0x00, 1, 8192, 8192, 0, None)
            self.connected = False
        else:
            self.pipename = pipename
            self.pipe = kernel32.CreateFileA(
                self.pipename, GENERIC_RDWR, 0, None, OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, None)
            self.connected = True

    def check_connection(self):
        if not self.connected:
            logger.debug("##++connect", stack_info=True)
            kernel32.ConnectNamedPipe(self.pipe, None)
            logger.debug("##--connect")
            self.connected = True

    def close(self):
        if self.pipe is not None:
            kernel32.CloseHandle(self.pipe)
            self.pipe = None

    def _read(self, size):
        self.check_connection()
        data = ctypes.create_string_buffer(size)
        szread = ctypes.c_int()
        logger.debug("++read %r", size)
        kernel32.ReadFile(self.pipe, data, size, byref(szread), None)
        logger.debug("--read %r\n%r", size, data.raw[:szread.value])
        return data.raw[:szread.value]

    def _write(self, data):
        self.check_connection()
        szwritten = ctypes.c_int()
        logger.debug("write %r", data)
        kernel32.WriteFile(self.pipe, data, len(data), byref(szwritten), None)


class FakePopen(subprocess.Popen):
    """Popen-alike based on a raw process handle."""

    def __init__(self, handle):
        super().__init__(None)
        self._handle = handle

    def terminate(self):
        kernel32.TerminateProcess(self._handle, -1)

    def _execute_child(self, *args, **kwds):
        pass


def spawn_sudo(proxy, user, password, domain):
    """Spawn the sudo slave process, returning proc and a pipe to message it.

    This function spawns the proxy app with administrator privileges, using
    ShellExecuteEx and the undocumented-but-widely-recommended "runas" verb.
    """
    pipe = Win32Pipe()
    exe = [sys.executable, "-c", "import runas; runas.run_proxy_startup()"]
    args = ["--runas-spawn-sudo", base.b64pickle(sys.path), base.b64pickle(proxy), pipe.pipename]
    exe = exe + args
    execinfo = SHELLEXECUTEINFO()
    execinfo.cbSize = sizeof(execinfo)
    execinfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    execinfo.hwnd = None
    execinfo.lpVerb = b"runas"
    execinfo.lpFile = exe[0].encode('cp1252')
    execinfo.lpParameters = subprocess.list2cmdline(exe[1:]).encode('cp1252')
    execinfo.lpDirectory = None
    execinfo.nShow = 0
    ShellExecuteEx(byref(execinfo))
    proc = FakePopen(execinfo.hProcess)
    logger.debug("##started process %r %r", proc.pid, pipe.pipename)
    return (proc, pipe)


def _spawn_sudo(proxy, user, password, domain):
    """Spawn the sudo slave process, returning proc and a pipe to message it.

    This function spawns the proxy app with administrator privileges, using
    ShellExecuteEx and the undocumented-but-widely-recommended "runas" verb.
    """
    exe = [sys.executable, "-c", "import runas; runas.run_proxy_startup()"]
    args = ["--runas-spawn-sudo", base.b64pickle(sys.path), base.b64pickle(proxy)]
    exe = exe + args
    nul = subprocess.DEVNULL
    pipe = subprocess.PIPE

    si = subprocess.STARTUPINFO()
    si.dwFlags = subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    kwds = dict(stdin=pipe, stdout=pipe, stderr=nul, close_fds=False, text=False,
                creationflags=subprocess.CREATE_NO_WINDOW, bufsize=0)
    # kwds = dict(text=False)
    logger.debug("start subprocess %r", exe)
    proc = subprocess.Popen(exe, **kwds)

    pipe = base.StdPipe(proc.stdout, proc.stdin)
    pipe.write(pickle.dumps((user, domain, password)))
    result = pickle.loads(pipe.read())
    if not result:
        proc.stdin.close()
        proc.stdout.close()
        proc.kill()
        raise RuntimeError("wrong credentials")

    logger.debug("wrote credencials %r", result)
    return proc, pipe


def run_proxy_startup():
    log_format = (
        "> runas %(created)f %(levelname)s %(name)s %(pathname)s(%(lineno)d): %(message)s")
    logging.basicConfig(level=logging.DEBUG, format=log_format, filename="runasc.log", filemode="w")
    logger.debug("_start proxy %r", sys.argv)
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "--runas-spawn-sudo":
            sys.path = base.b64unpickle(sys.argv[2])
            proxy = base.b64unpickle(sys.argv[3])
            pipename = sys.argv[4]
            logger.debug("_loaded pipe %r", pipename)
            pipe = Win32Pipe(pipename)
            logger.debug("_connected to pipe %r", pipename)

            """
            user, domain, password = pickle.loads(pipe.read())
            try:
                handle = win32security.LogonUser(
                    user, domain, password, win32con.LOGON32_LOGON_INTERACTIVE,
                    win32con.LOGON32_PROVIDER_DEFAULT)
                win32security.ImpersonateLoggedOnUser(handle)
                pipe.write(pickle.dumps(True))
            except Exception as e:
                logger.exception("error impersonating %r\n%r", e, (user, domain, password))
                pipe.write(pickle.dumps(False))
                sys.exit(1)
            """

            proxy.run(pipe)
            logger.debug("_done")
            # win32security.RevertToSelf()
            # handle.close()
            sys.exit(0)
    except BaseException as e:
        logger.exception("error %r", e)
