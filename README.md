# Man-in-the-middle SSH Server

## Objective

Provide students the ability to collect SSH related data (login attempts, keystrokes) without the need for them to build their own SSH server.

See this [wiki page](https://github.com/UMD-ACES/MITM/wiki/Data-Collection) about the information collected by the MITM SSH server.

## Expectations

This program as is should only facilitate students with the collection of SSH related data.

This program is not meant to facilitate the following:
* Honeypot Architecture Setup
* Recycling
* Monitoring
* Data Analysis

However, students may modify this program as they wish including faciliting the above while following the [rules](https://github.com/UMD-ACES/MITM/blob/master/README.md#rules) described at a later section.

## Resources

Please see the rest of this README page and check out the [wiki](https://github.com/UMD-ACES/MITM/wiki) pages.


## Configuration

| Setting | Type | Explanation |
| :--------:| :----: | :------------|
| local | Boolean | Runs the MITM SSH Server without requiring a container. Warning messages will display and there will be limitations (e.g. pty mode is disabled). |
| debug   | Boolean | MITM Debug Output. Good option to have enabled when building your honeypot ecosystem. Provides detailed logs of the actions that the MITM takes in real time. |
| logToInstructor.enabled | Boolean | Logging the MITM operations into a DB (must be **enabled** unless otherwise stated by an instructor or TA) |
| logging.streamOutput | String | Folder where the attacker streams are placed (keystrokes, screen display) |
| logging.loginAttempts | String | Folder where all login attempts are being logged |
| logging.logins | String | Folder where all logins are being logged |
| server.maxAttemptsPerConnection | Integer | Number of login attempts before the server force closes on the SSH client |
| server.listenIP | String | The IP address to listen on |
| server.identifier | String | The SSH server identifier string sent to the SSH client |
| server.banner | String | A message sent to clients upon connection to the MITM |
| autoAccess.enabled | Boolean | If true, then enable automatic access to the honeypot after a certain number of login attempts (normal distribution using mean and standard deviation values). Can be manually set in the command line. |
| autoAccess.cacheSize | Integer | Number of attacker IPs to hold when autoAccess is turned "on" . This value is required to not overwhelm the host memory. |
| autoAccess.barrier.normalDist.enabled | Boolean | Enable normal distribution to calculate the login attempt threshold per attacker |
| autoAccess.barrier.normalDist.mean | Integer | Mean number of login attempts before automatic access |
| autoAccess.barrier.normalDist.standardDeviation | Integer | Standard Deviation. Automatic access follows a normal distribution. |
| autoAccess.barrier.fixed.enabled | Boolean | Enable fixed login attempts threshold |
| autoAccess.barrier.fixed.attempts | Number | Number of login attempts |


## Start the MITM server

View this wiki page to learn about starting the MITM SSH Server (https://github.com/UMD-ACES/MITM/wiki/Spawn-a-MITM-SSH-Server-instance#launch-a-mitm-ssh-server)

## Running MITM in the background

Please check this [wiki page](https://github.com/UMD-ACES/MITM/wiki/Running-in-the-Background) if you would like to run the MITM in the background

## Automatic Access

Allows an attacker to successfully authenticate after a certain number of login attempts.

Before using automatic access, please read the following [wiki page](https://github.com/UMD-ACES/MITM/wiki/Automatic-Access)

## Rules
1. Do not add/edit/delete any code that are in the instructor blocks.
2. You must enable the logToInstructor functionality.
3. If you are having issues with a particular MITM instance, please make sure to communicate the session id

## Stay up to date
Run `git pull origin master` inside the /root/MITM directory.

## Documentation
[Wiki Page](https://github.com/UMD-ACES/MITM/wiki)

## Authors
Louis-Henri Merino  
Franz Payer  
Zhi Xiang Lin  

## License
MIT License
