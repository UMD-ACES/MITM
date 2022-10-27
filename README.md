# Man-in-the-Middle (MITM) SSH Server

## Objective

Provide students with the ability to collect SSH related data (login attempts, keystrokes) without the need to build their own SSH server.

## Expectations

This program as is should only facilitate students with the collection of SSH related data.

This program is not meant to facilitate the following:
* Honeypot Architecture Setup
* Recycling
* Monitoring
* Data Analysis

However, students may modify this program as they wish to add or change desired functionality.

# Data Collection
This program will collect 3 main types of data:
1. Authentication attempts - including client IP, username, and password
2. Successful logins - client IP
3. Session stream - raw session stream between the client & SSH server
4. Session keystrokes - all the individual keystrokes and the parsed lines

## Start the MITM server

Run `node mitm.js -n <container name> -i <container internal IP> -p <MITM listening port>` to start the MITM server.

Run with the `--debug` flag for verbose debug output. This is helpful when first setting up the server.

## Configuration

Run with the `--help` option to see full list of configurable options and defaults.

## Automatic Access

This feature allows an attacker to successfully authenticate after a certain number of login attempts.

Auto-access will only be available for 1 automatic access per MITM process, meaning that once MITM is triggered once, it will be disabled.

Furthermore, enabling auto-access will essentially disable authentication checks against the SSH server itself until auto-access strategy triggers.

However, auto-access does not block anything, i.e. it will not block IP addresses and it will not block other user accounts after triggering. The MITM server only intercepts data for recording purposes or for allowing automatic access.

Enable auto-access by toggling the `--auto-access` option, then you must configure one of the two strategies available:
1. normal distribution
2. fixed attempt

For normal distribution strategy, the server will allow auto-access after `--auto-access-normal-distribution-mean` number of attempts with the consideration of `--auto-access-normal-distribution-std-dev` to randomize the number of attempts required.

For fixed attempt strategy, the server will simply allow auto-access after `--auto-access-fixed` number of attempts.

**Important Note:** The container makes the ultimate decision. The container's `/etc/ssh/sshd_config` file has the ability to deny login credentials even though they may be valid (e.g. `DenyUsers root` or `PermitRootLogin no`)

## Port Redirection

If you use `iptables` to redirect SSH traffic to the MITM server and you redirect it to `localhost` (`127.0.0.1`), you may need to enable the following system option:
```
sysctl -w net.ipv4.conf.all.route_localnet=1
```
(depending on your system, this configuration may not persist past a reboot)

## Running MITM in the background

Please check this [wiki page](https://github.com/UMD-ACES/MITM/wiki/Running-in-the-Background) if you would like to run the MITM in the background

Note the dates on the wiki pages, some of the pages may be out of date

## Stay up to date
Run `git pull origin main` inside the /root/MITM directory.

## Additional Documentation
Some of the [Wiki Page](https://github.com/UMD-ACES/MITM/wiki) may be out of date, please review the information carefully.

## License
MIT License
