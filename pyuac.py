#!/usr/bin/env python

"""User Access Control for Microsoft Windows Vista and higher.  This is
only for the Windows platform.

This will relaunch either the current script - with all the same command
line parameters - or else you can provide a different script/program to
run.  If the current user doesn't normally have admin rights, he'll be
prompted for an admin password. Otherwise he just gets the UAC prompt.

Note that the prompt may simply shows a generic python.exe with "Publisher:
Unknown" if the python.exe is not signed.

This is meant to be used something like this::

    if not pyuac.is_user_admin():
        return pyuac.run_as_admin()

    # otherwise carry on doing whatever...
"""

# https://gist.github.com/sylvainpelissier/ff072a6759082590a4fe8f7e070a4952

import os
import sys
import traceback


def is_user_admin():
    """@return: True if the current user is an 'Admin' whatever that
    means (root on Unix), otherwise False.

    Warning: The inner function fails unless you have Windows XP SP2 or
    higher. The failure causes a traceback to be printed and this
    function to return False.
    """

    if os.name != 'nt':
        raise RuntimeError("This function is only implemented on Windows.")

    import ctypes
    # WARNING: requires Windows XP SP2 or higher!
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        traceback.print_exc()
        print("Admin check failed, assuming not an admin.")
        return False


def run_as_admin(cmdline=None, wait=True):
    """Attempt to relaunch the current script as an admin using the same
    command line parameters.  Pass cmdline in to override and set a new
    command.  It must be a list of [command, arg1, arg2...] format.

    Set wait to False to avoid waiting for the sub-process to finish. You
    will not be able to fetch the exit code of the process if wait is
    False.

    Returns the sub-process return code, unless wait is False in which
    case it returns None.

    @WARNING: this function only works on Windows.
    """

    if os.name != 'nt':
        raise RuntimeError("This function is only implemented on Windows.")

    import win32api, win32con, win32event, win32process
    from win32com.shell.shell import ShellExecuteEx
    from win32com.shell import shellcon

    python_exe = sys.executable

    if cmdline is None:
        cmdline = [python_exe] + sys.argv
    elif not isinstance(cmdline, (tuple, list)):
        raise ValueError("cmdline is not a sequence.")
    cmd = '"%s"' % (cmdline[0],)
    # XXX TODO: isn't there a function or something we can call to massage command line params?
    params = " ".join(['"%s"' % (x,) for x in cmdline[1:]])
    show_cmd = win32con.SW_SHOWNORMAL
    verb = 'runas'  # causes UAC elevation prompt.

    # print "Running", cmd, params

    # ShellExecute() doesn't seem to allow us to fetch the PID or handle
    # of the process, so we can't get anything useful from it. Therefore
    # the more complex ShellExecuteEx() must be used.

    # procHandle = win32api.ShellExecute(0, lpVerb, cmd, params, cmdDir, showCmd)

    proc_info = ShellExecuteEx(nShow=show_cmd,
                               fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
                               lpVerb=verb,
                               lpFile=cmd,
                               lpParameters=params)

    if wait:
        proc_handle = proc_info['hProcess']
        win32event.WaitForSingleObject(proc_handle, win32event.INFINITE)
        rc = win32process.GetExitCodeProcess(proc_handle)
    else:
        rc = None

    return rc


def test():
    """A simple test function; check if we're admin, and if not relaunch
    the script as admin."""
    if not is_user_admin():
        print("You're not an admin.", os.getpid(), "params: ", sys.argv)
        run_as_admin()
    else:
        print("You are an admin!", os.getpid(), "params: ", sys.argv)
    input('Press Enter to exit.')


if __name__ == "__main__":
    res = test()
    sys.exit(res)
