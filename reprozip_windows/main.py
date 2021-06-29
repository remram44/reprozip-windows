# https://adamtheautomator.com/procmon/#Sysinternals_Live
# Saves in PML format, but can export as CSV

from collections import Counter
import csv
from datetime import datetime, timedelta
import os.path
import pathlib
import pkg_resources
import pyuac
import re
import subprocess
import sys
import time


PROCMON = 'C:\\Program Files (x86)\\Procmon\\Procmon.exe'


@pyuac.main_requires_admin()
def main():
    # Start tracing
    config = pkg_resources.resource_filename('reprozip_windows', 'procmonconfig.pmc')
    procmon = subprocess.Popen(
        [
            PROCMON, '/Minimized', '/AcceptEula',
            '/LoadConfig', config,
            '/Quiet',
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
    reader = ProcmonCSVReader()
    reader.read_csv('temp.csv')
    for op in reader.operations:
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


class ProcmonCSVReader(object):
    def __init__(self):
        self.time_reference = None

        self.filename = None
        self.row_number = None

        self.operations = []
        self.traced_processes = set()
        self.unknown_operations = Counter()
        self.unknown_access_modes = Counter()

    def read_csv(self, file):
        try:
            # Accept a path, open the file
            if isinstance(file, (str, bytes, pathlib.Path)):
                with open(file, 'r', encoding='utf-8-sig') as fp:
                    self.filename = str(file)
                    return self._read_csv(fp)
            else:
                self.filename = repr(file)
                return self._read_csv(file)
        finally:
            self.filename = None
            self.row_number = None

    def _read_csv(self, file):
        if self.time_reference is None:
            self.time_reference = datetime.utcnow()

        # Open CSV
        reader = csv.reader(file)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError("Empty trace file")
        else:
            if header != [
                "Time of Day", "Process Name", "PID", "Operation", "Path",
                "Result", "Detail",
            ]:
                raise ValueError("Wrong column names")

        # Iterate on rows
        for idx, row in enumerate(reader, 2):
            self.row_number = idx
            self.process_row(*row)

        if self.unknown_operations:
            print(
                "\nUnknown operations:\n%s" % '\n'.join(
                    '    %s (%d)' % p
                    for p in self.unknown_operations.items()
                ),
                file=sys.stderr,
            )
        if self.unknown_access_modes:
            print(
                "\nUnknown access modes:\n%s" % '\n'.join(
                    '    %s (%d)' % p
                    for p in self.unknown_access_modes.items()
                ),
                file=sys.stderr,
            )

    def parse_time(self, time):
        # Parse fields
        m = re.match(
            r'([0-9]{1,2}):([0-9]{2}):([0-9]{2}).([0-9]+) (AM|PM)$',
            time,
        )
        if m is None:
            raise ValueError("Invalid time %r" % time)
        hour, minute, second, frac, am_pm = m.groups()
        hour = int(hour, 10)
        minute = int(minute, 10)
        second = int(second, 10)
        # AM/PM
        if am_pm == 'PM':
            hour += 12
        # Turn fractional part into microseconds (6 digits)
        microsecond = frac[:6] + ('0' * (6 - len(frac)))
        microsecond = int(microsecond, 10)

        # Build datetime object, filling from reference
        ref = self.time_reference
        date = datetime(
            ref.year, ref.month, ref.day,
            hour, minute, second, microsecond,
        )
        # If we're ahead, it's probably a different day
        # This catches problems around midnight
        if (hour, minute) > (ref.hour, ref.minute):
            date -= timedelta(days=1)
        return date

    def parse_access_mode(self, modes):
        modes = set(modes)
        unknown = modes - {
            'Execute/Traverse', 'Generic Read', 'Read Attributes',
            'Read Data/List Directory', 'Synchronize', 'Generic Write',
        }
        for mode in unknown:
            self.unknown_access_modes[mode] += 1
        if 'Generic Write' in modes:
            return 'write'
        else:
            return 'read'

    def process_row(
        self, time, procname, pid, operation, path, result, details,
    ):
        time = self.parse_time(time)

        if (
            not self.traced_processes and operation == 'Process Start'
            and procname == os.path.basename(sys.executable)
        ):
            print("Tracing %s: %s" % (pid, procname), file=sys.stderr)
            self.traced_processes.add(pid)
        elif pid not in self.traced_processes:
            return

        if operation in IGNORED_OPERATIONS:
            pass
        elif operation == 'Load Image':
            if result == 'SUCCESS':
                self.operations.append(('read', path))
        elif operation == 'CreateFile':
            if result == 'SUCCESS':
                info = parse_details(details)
                mode = self.parse_access_mode(info['Desired Access'])
                self.operations.append((mode, path))
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
                self.operations.append(('create-proc', childpid, childcmd))
        else:
            self.unknown_operations[operation] += 1


if __name__ == '__main__':
    main()
