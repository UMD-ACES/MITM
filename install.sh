#!/usr/bin/env bash

sudo apt update

sudo apt install -y build-essential curl gcc g++ make

curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -

sudo apt install -y nodejs

cd "$(dirname "$0")"

npm install
