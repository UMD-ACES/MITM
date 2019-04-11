#!/usr/bin/env bash

apt-get install -y sudo build-essential curl

curl -sL https://deb.nodesource.com/setup_6.x | sudo bash -

cd "$(dirname "$0")"

npm install