#!/usr/bin/env bash

sudo apt-get update

sudo apt-get install -y sudo build-essential curl php-cli gcc g++ make

curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -

sudo apt-get install -y nodejs

cd "$(dirname "$0")"

sudo npm install
