#!/usr/bin/env python3

import subprocess
import sys

if __name__ == '__main__':
    args = sys.argv
    cid = args[1]
    command = args[2:]
    retcode = subprocess.call(['lxc-attach', '-n', cid, '--'] + command)
    sys.exit(retcode)
