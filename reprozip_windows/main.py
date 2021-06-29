# https://adamtheautomator.com/procmon/#Sysinternals_Live
# Saves in PML format, but can export as CSV

from collections import Counter
import csv
import os.path
import pyuac
import re
import subprocess
import sys
import time


PROCMON = 'C:\\Program Files (x86)\\Procmon\\Procmon.exe'


def main():
    # Need to be admin to run procmon
    if not pyuac.isUserAdmin():
        pyuac.runAsAdmin()
        return

    # Start tracing
    procmon = subprocess.Popen(
        [
            PROCMON, '/Minimized', '/AcceptEula', '/NoFilter', '/Quiet',
            '/BackingFile', 'temp.pml',
        ],
    )
    time.sleep(3)

    # Run the process
    print("Running: %s" % ' '.join(sys.argv[1:]))
    code = subprocess.call(sys.argv[1:])
    print("Process finished, returned %d" % code)

    # Stop tracing
    time.sleep(3)
    subprocess.check_call([PROCMON, '/Terminate'])
    procmon.wait()

    # Convert log to CSV
    subprocess.check_call([
        PROCMON,
        '/OpenLog', 'temp.pml',
        '/SaveAs', 'temp.csv',
    ])

    # Read CSV
    operations = read_trace('temp.csv')
    for op in operations:
        print(op)


def parse_details(details):
    parsed = {}
    pos = 0
    while True:
        # Read the key
        colon = details.find(':', pos)
        if colon == -1:
            break
        key = details[pos:colon]
        pos = colon + 2

        # Read the values
        value_end = details.find(':', pos)
        if value_end == -1:
            value_end = len(details)
        values = []
        while True:
            comma = details.find(',', pos)
            if comma == -1 or comma > value_end:
                break
            value = details[pos:comma]
            if value not in ('n/a', 'None'):
                values.append(value)
            pos = comma + 2
        parsed[key] = values
    return parsed


IGNORED_OPERATIONS = {
    # Non-file events
    'Process Start', 'Thread Create', 'Process Exit', 'Thread Exit',
    # Operations on files that are already open
    'CloseFile', 'RegCloseKey', 'ReadFile', 'WriteFile', 'RegQueryValue',
    'CreateFileMapping', 'QueryDirectory', 'IRP_MJ_CLOSE',
    'QueryNameInformationFile', 'QueryBasicInformationFile',
    'QueryStandardInformationFile',
    'QueryInformationVolume', 'QueryAllInformationFile', 'QueryEAFile',
    # Operations on registry keys that are already open
    'RegSetInfoKey', 'RegEnumKey', 'RegQueryKey', 'RegEnumValue',
    # I don't know
    'Process Profiling',
    'QueryOpen',
    'FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION',
}


def read_trace(filename):
    traced_processes = set()
    operations = []
    unknown_operations = Counter()
    unknown_modes = Counter()

    def parse_access(access_modes):
        access_modes = set(access_modes)
        unknown = access_modes - {
            'Execute/Traverse', 'Generic Read', 'Read Attributes',
            'Read Data/List Directory', 'Synchronize', 'Generic Write',
        }
        for mode in unknown:
            unknown_modes[mode] += 1
        if 'Generic Write' in access_modes:
            return 'write'
        else:
            return 'read'

    with open(filename, 'r', encoding='utf-8-sig') as csvfile:
        reader = csv.reader(csvfile)

        for idx, row in enumerate(reader):
            time, procname, pid, operation, path, result, details = row

            if (
                not traced_processes and operation == 'Process Start'
                and procname == os.path.basename(sys.executable)
            ):
                print("Tracing %s: %s" % (pid, procname), file=sys.stderr)
                traced_processes.add(pid)
            elif pid not in traced_processes:
                continue

            if operation in IGNORED_OPERATIONS:
                pass
            elif operation == 'Load Image':
                if result == 'SUCCESS':
                    operations.append(('read', path))
            elif operation == 'CreateFile':
                if result == 'SUCCESS':
                    info = parse_details(details)
                    mode = parse_access(info['Desired Access'])
                    operations.append((mode, path))
            elif operation == 'RegOpenKey':
                pass  # TODO
            elif operation == 'Process Create':
                m = re.match(r'^PID: ([0-9]+), Command line: .*$', details)
                if m is None:
                    print(
                        "Invalid process creation details: %r" % details,
                        file=sys.stderr,
                    )
                else:
                    childpid, childcmd = m.groups()
                    operations.append(('create-proc', childpid, childcmd))
            else:
                unknown_operations[operation] += 1

    if unknown_operations:
        print(
            "\nUnknown operations:\n%s" % '\n'.join(
                '    %s (%d)' % p
                for p in unknown_operations.items()
            ),
            file=sys.stderr,
        )
    if unknown_modes:
        print(
            "\nUnknown access modes:\n%s" % '\n'.join(
                '    %s (%d)' % p
                for p in unknown_modes.items()
            ),
            file=sys.stderr,
        )

    return operations


if __name__ == '__main__':
    main()
