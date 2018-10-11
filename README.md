# Man-in-the-middle SSH Server

## Configuration

| Setting | Type | Explanation |
| :--------:| :----: | :------------|
| local | Boolean | Runs the MITM SSH Server without requiring a container. Warning messages will display and there will be limitations (e.g. pty mode is disabled). |
| debug   | Boolean | MITM Debug Output. Good option to have enabled when building your honeypot ecosystem. Provides detailed logs of the actions that the MITM takes in real time. |
| logToInstructor.enabled | Boolean | Logging the MITM operations into a DB (must be **enabled** unless otherwise stated by an instructor or TA) |
| attacker.streamOutput | String | Folder where the attacker output streams are placed |
| server.maxAttemptsPerConnection | Integer | Number of login attempts before the server force closes on the SSH client |
| server.listenIP | String | The IP address to listen on |
| server.identifier | String | The SSH server identifier string sent to the SSH client |
| autoAccess.enabled | Boolean | If true, then enable automatic access to the honeypot after a certain number of login attempts (normal distribution using mean and standard deviation values). Can be manually set in the command line. |
| autoAccess.cacheSize | Integer | Number of attacker IPs to hold when autoAccess is turned "on" . This value is required to not overwhelm the host memory. |
| autoAccess.barrier.normalDist.enabled | Boolean | Enable normal distribution to calculate the login attempt threshold per attacker |
| autoAccess.barrier.normalDist.mean | Integer | Mean number of login attempts before automatic access |
| autoAccess.barrier.normalDist.standardDeviation | Integer | Standard Deviation. Automatic access follows a normal distribution. |
| autoAccess.barrier.fixed.enabled | Boolean | Enable fixed login attempts threshold |
| autoAccess.barrier.fixed.attempts | Number | Number of login attempts |

##

## Start the MITM server

```bash
node /root/MITM/mitm/index.js <class_groupID> <port> <container_ip> <container_id> [autoAccessEnable] [config file]
```
Example A:  
```bash
node /root/MITM/mitm/index.js HACS200_1A 10000 172.20.0.2 101
```
Example B:  
```bash
node /root/MITM/mitm/index.js HACS200_1A 10000 172.20.0.2 101 true
```
Example C (view setting up multiple config files [here](https://github.com/UMD-ACES/MITM/wiki/Multiple-config-files)):
```bash
node /root/MITM/mitm/index.js HACS200_1A 10000 172.20.0.2 101 true mitm2.js
```

## Background

Please check this [wiki page](https://github.com/UMD-ACES/MITM/wiki/Running-in-the-Background) if you would like to run the MITM in the background

## Rules
1. Do not add/edit/delete any code that are in the instructor blocks.
2. You must enable the logToInstructor functionality.
3. If you are having issues with a particular MITM instance, please make sure to communicate the session id

## Stay up to date
`git pull origin master` inside the /root/MITM directory.

## Documentation
[Wiki Page](https://github.com/UMD-ACES/MITM/wiki)

## Automatic Access

Allows an attacker to successfully authenticate after a certain number of login attempts.

## Authors
Louis-Henri Merino  
Franz Payer  
Zhi Xiang Lin  

## License
MIT License


