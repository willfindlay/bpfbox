import os, sys

from bcc import syscall

__syscalls = {key: value.decode('utf-8') for key, value in syscall.syscalls.items()}
__syscalls_reverse = {value: key for key, value in __syscalls.items()}
# Patch pread64 and pwrite64 into table
__syscalls_reverse['pread64']  = __syscalls_reverse['pread']
__syscalls_reverse['pwrite64'] = __syscalls_reverse['pwrite']

def syscall_number(name):
    try:
        return __syscalls_reverse[name.lower().strip()]
    except KeyError:
        return -1

def syscall_name(num):
    try:
        return __syscalls[num]
    except KeyError:
        return '[unknown]'

def check_root():
    """
    Check for root permissions.
    """
    return os.geteuid() == 0

def drop_privileges(function):
    """
    Decorator to drop root privileges.
    """
    def inner(*args, **kwargs):
        # Get sudoer's UID
        try:
            sudo_uid = int(os.environ['SUDO_UID'])
        except (KeyError, ValueError):
            print("Could not get UID for sudoer", file=sys.stderr)
            return
        # Get sudoer's GID
        try:
            sudo_gid = int(os.environ['SUDO_GID'])
        except (KeyError, ValueError):
            print("Could not get GID for sudoer", file=sys.stderr)
            return
        # Make sure groups are reset
        try:
            os.setgroups([])
        except PermissionError:
            pass
        # Drop root
        os.setresgid(sudo_gid, sudo_gid, -1)
        os.setresuid(sudo_uid, sudo_uid, -1)
        # Execute function
        ret = function(*args, **kwargs)
        # Get root back
        os.setresgid(0, 0, -1)
        os.setresuid(0, 0, -1)
        return ret
    return inner
