#!/bin/bash

CONTAINER=$1
USERNAME=$2
PASSWORD=$3

lxc-attach -n "$CONTAINER" -- usermod -p "$(openssl passwd "$PASSWORD")" "$USERNAME"
