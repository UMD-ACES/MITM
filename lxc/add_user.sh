#!/bin/bash

CONTAINER=$1
USERNAME=$2

lxc-attach -n "$CONTAINER" -- useradd "$USERNAME" -m -s /bin/bash > /dev/null 2>&1 || true
