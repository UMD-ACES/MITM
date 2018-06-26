#!/usr/bin/env python3

import subprocess
import argparse
import sys
import os

def mount_container(name):
    # Create mount point (/media/<name>)
    os.makedirs('/media/'+name, exist_ok=True)

    # Assume it's already mounted if things exist in the directory
    if len(os.listdir('/media/'+name)) > 0:
        return

    retcode = subprocess.call(['lvchange', '-ay', '/dev/pve/vm-'+name+'-disk-1'])

    if retcode != 0:
        print("Error with lvchange", file=sys.stderr)
        sys.exit(1)

    # Mount image file to /media/<name> if necessary
    retcode = subprocess.call(['mount',
                               '/dev/pve/vm-'+name+'-disk-1',
                               '/media/'+name])
    if retcode != 0:
        print("Error mounting container", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    # Set up argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--name',
                        help='Name of container (ID)')
    #read arguments
    args = parser.parse_args()

    #Check for correct parameters
    if not args.name:
        print('You must provide the container name')
        sys.exit(1)

    # Ensure container has been mounted
    mount_container(args.name)
