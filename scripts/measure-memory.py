"""Read-only Linux service RSS/PSS and cgroup sampling; never reads process memory.

Run on the host: python3 measure-memory.py [--samples 30] [--interval 1].
Only mapping accounting, process counters and cgroup counters are emitted.
Anonymous mappings include allocator arenas; they are not a live-object heap profile.
"""
import argparse
from collections import defaultdict
import datetime
import json
from pathlib import Path
import re
import subprocess
import time


def counters(path):
    result = {}
    for line in path.read_text().splitlines():
        if re.match(r'^[0-9a-f]+-[0-9a-f]+ ', line):
            continue
        key, sep, value = line.partition(":")
        if sep and value.strip().split() and value.strip().split()[0].isdigit():
            result[key] = int(value.strip().split()[0])
    return result


def snapshot(pid, cgroup):
    root = Path('/proc') / str(pid)
    groups = defaultdict(lambda: defaultdict(int))
    category = None
    for line in (root / 'smaps').read_text().splitlines():
        if re.match(r'^[0-9a-f]+-[0-9a-f]+ ', line):
            fields = line.split(maxsplit=5)
            name = fields[5] if len(fields) == 6 else ''
            if name == '[heap]':
                category = 'heap'
            elif name.startswith('[stack'):
                category = 'stack'
            elif name.endswith('/mail-bridge-rust'):
                category = 'executable'
            elif not name:
                category = 'anonymous'
            elif name.startswith('['):
                category = 'kernel_special'
            elif '.so' in name:
                category = 'shared_libraries'
            else:
                category = 'other_file'
        elif category and ':' in line:
            key, value = line.split(':', 1)
            if key in ('Size', 'Rss', 'Pss', 'Private_Clean', 'Private_Dirty', 'Shared_Clean', 'Shared_Dirty', 'Anonymous', 'Swap'):
                groups[category][key] += int(value.split()[0])
    status = counters(root / 'status')
    cg = Path('/sys/fs/cgroup') / cgroup.lstrip('/')
    cgstat = dict(line.split() for line in (cg / 'memory.stat').read_text().splitlines())
    return {
        'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'pid': pid,
        'status': {key: status.get(key) for key in ('VmRSS', 'VmHWM', 'VmSize', 'VmSwap', 'Threads')},
        'groups_kib': dict(groups),
        'rollup_kib': counters(root / 'smaps_rollup'),
        'cgroup_bytes': {'current': int((cg / 'memory.current').read_text()), **{key: int(value) for key, value in cgstat.items()}},
        'fds': len(list((root / 'fd').iterdir())),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=int, default=30)
    parser.add_argument('--interval', type=float, default=1)
    args = parser.parse_args()
    if args.samples < 1 or args.interval < 0:
        parser.error('samples must be positive and interval nonnegative')
    properties = subprocess.check_output(['systemctl', 'show', 'mail-bridge-rust', '-p', 'MainPID', '-p', 'ControlGroup'], text=True)
    props = dict(line.split('=', 1) for line in properties.splitlines())
    pid = int(props['MainPID'])
    if pid <= 0:
        parser.error('service is not running')
    for index in range(args.samples):
        print(json.dumps(snapshot(pid, props['ControlGroup'])), flush=True)
        if index + 1 < args.samples:
            time.sleep(args.interval)


if __name__ == '__main__':
    main()
