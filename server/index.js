/************************************************************************************
 * ---------------------- Required Packages START Block -----------------------------
 ************************************************************************************/

const path            = require('path'),
      fs              = require('fs'),
      zlib            = require('zlib'),
      initialize      = require('./keys'),
      readline        = require('readline'),
      child_process   = require('child_process'),
      Stream          = require('stream'),
      ssh2            = require('ssh2'),
      os              = require('os'),
      printAscii      = require('print-ascii'),
      d3_random       = require('d3-random'),
      seedrandom      = require('seedrandom'),
      moment          = require('moment'),
      fixedQueue      = require('fixedqueue').FixedQueue,
      crypt3          = require('@idango/crypt3/sync'),
      commander       = require('commander');

const version = 2;

const { spawnSync, execSync } = child_process;

/************************************************************************************
 * ---------------------- Required Packages END Block -------------------------------
 ************************************************************************************/

/************************************************************************************
 * ---------------------- MITM Global Variables START Block -------------------------
 ************************************************************************************/

// Keep track of lxc streams
let lxcStreams = []

// Cleanup Variable
let cleanup = false;

// SSH Keys - try to load the key from the container; otherwise, use the default key.
let DEFAULT_KEYS = {
  PRIVATE: fs.readFileSync(path.resolve(__dirname, 'defaultKey')),
  PUBLIC: fs.readFileSync(path.resolve(__dirname, 'defaultKey.pub')),
};

// Logging files
let loginAttempts, logins, logouts, delimiter = ';';

/************************************************************************************
 * ---------------------- MITM Global Variables END Block ---------------------------
 ************************************************************************************/

commander.program
  .option('-d, --debug', 'Debug mode', false)
  .requiredOption('-n, --container-name <name>', 'Container name')
  .requiredOption('-i, --container-ip <ip address>', 'Container internal IP address')
  .requiredOption('-p, --mitm-port <number>', 'MITM server listening port', parseInt)
  .option('-l, --mitm-ip <ip address>', 'MITM server listening ip address', '127.0.0.1')
  .option('-a, --auto-access', 'Toggle to enable auto-access, must configure one of the auto-access strategies below', false)
  .option('--auto-access-normal-distribution-mean <number>', 'Auto-Access Normal Distribution Strategy: Mean number of attempts before allowing attacker', parseInt)
  .option('--auto-access-normal-distribution-std-dev <number>', 'Auto-Access Normal Distribution Strategy: Standard deviation from the mean to randomize', parseInt)
  .option('--auto-access-fixed <number>', 'Auto-Access Fixed Strategy: Number of attempts before allowing attacker', parseInt)
  .option('--auto-access-cache <number>', 'Size of the cache to track IP addresses', 5000)
  .option('--max-attempts-per-connection <number>', 'Number of credential attempts to allow per single SSH connection', 6)
  .option('--ssh-server-identifier <string>', 'SSH Server Identifier field to advertise to SSH clients', 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2')
  .option('--ssh-server-banner-file <file path>', 'File path to the SSH server banner to show SSH clients when they connect')
  .option('--container-mount-path-prefix <string>', 'The base directory for where all containers are mounted', '/var/lib/lxc')
  .option('--container-mount-path-suffix <string>', 'The sub directory name where the container file system is located', 'rootfs/')
  .option('--logging-attacker-streams <string>', 'The directory to log all attacker session streams', path.resolve(__dirname, '../logs/session_streams'))
  .option('--logging-authentication-attempts <string>', 'The directory to log all attacker authentication attempts', path.resolve(__dirname, '../logs/authentication_attempts'))
  .option('--logging-logins <string>', 'The directory to log all successful attacker logins', path.resolve(__dirname, '../logs/logins'))
  .option('--logging-logouts <string>', 'The directory to log all attacker logouts', path.resolve(__dirname, '../logs/logouts'))
  .option('--logging-keystrokes <string>', 'The directory to log all attacker keystrokes', path.resolve(__dirname, '../logs/keystrokes'))
;

commander.program.parse();

const options = commander.program.opts();

const {
  debug,
  containerName,
  containerIp,
  mitmPort,
  mitmIp,
  autoAccess,
  autoAccessNormalDistributionMean,
  autoAccessNormalDistributionStdDev,
  autoAccessFixed,
  autoAccessCache,
  maxAttemptsPerConnection,
  sshServerIdentifier,
  sshServerBannerFile,
  containerMountPathPrefix,
  containerMountPathSuffix,
  loggingAttackerStreams,
  loggingAuthenticationAttempts,
  loggingLogins,
  loggingLogouts,
  loggingKeystrokes,
} = options;

if (debug) {
  console.log('Started with the following options:');
  console.log(options);

  if (/^127\./.test(mitmIp)) {
    console.log('[WARNING] Your MITM server is listening on the localhost IP address, you will need to set the following sysctl option for iptables to port forward to a localhost IP:');
    console.log('sysctl -w net.ipv4.conf.all.route_localnet=1');
  }
}

/************************************************************************************
 * ---------------------- Logging START Block ---------------------------------------
 ************************************************************************************/

function debugLog(message) {
  if (debug) {
    message = moment().format('YYYY-MM-DD HH:mm:ss.SSS') + ' - [Debug] ' + message;
    console.log(message);
  }
}

function infoLog(message) {
  message = moment().format('YYYY-MM-DD HH:mm:ss.SSS') + ' - [Info] ' + message;
  console.log(message);
}

function errorLog(message) {
  message = moment().format('YYYY-MM-DD HH:mm:ss.SSS') + ' - [Error] ' + message;
  console.error(message);
}

/************************************************************************************
 * ---------------------- Logging END Block -----------------------------------------
 ************************************************************************************/

// Automatic Access Variables
let autoAccessEnabled = autoAccess;
let autoAccessThresholdAchieved = false;
let autoRandomNormal = null;
const autoIPs = autoAccessEnabled ? new fixedQueue(autoAccessCache) : null;
const containerMountPath = path.join(containerMountPathPrefix, containerName, containerMountPathSuffix);

// Set up Normal Distribution Random Generator if enabled
if (autoAccess) {
  if (autoAccessNormalDistributionMean >= 0) {
    if (!(autoAccessNormalDistributionStdDev >= 0)) {
      console.log('[ERROR] Auto Access normal distribution strategy is missing the standard deviation configuration');
      process.exit(1);
    }
    autoRandomNormal = d3_random.randomNormal.source(seedrandom())(autoAccessNormalDistributionMean, autoAccessNormalDistributionStdDev);
  } else if (!(autoAccessFixed >= 0)) {
    console.log('[ERROR] Auto Access is enabled but none of the threshold strategies are configured');
    process.exit(1);
  }
}

// loads private and public keys from container if possible
const hostKeys = initialize.loadKeys(containerMountPath, containerName);

infoLog('MITM Version: ' + version);
infoLog('Auto Access Enabled: ' + autoAccessEnabled);
debugLog('[Init] Auto Access Theshold Achieved: ' + autoAccessThresholdAchieved);

// makes the attacker session screen output folder if not already created
initialize.makeOutputFolder(loggingAttackerStreams);
initialize.makeOutputFolder(loggingAuthenticationAttempts);
initialize.makeOutputFolder(loggingLogins);
initialize.makeOutputFolder(loggingLogouts);
initialize.makeOutputFolder(loggingKeystrokes);

loginAttempts   = fs.createWriteStream(path.resolve(loggingAuthenticationAttempts, containerName + '.log'), { flags: 'a' });
logins          = fs.createWriteStream(path.resolve(loggingLogins, containerName + '.log'), { flags: 'a' });
logouts          = fs.createWriteStream(path.resolve(loggingLogouts, containerName + '.log'), { flags: 'a' });

startServer(hostKeys, mitmPort);

/**
 * Start the main SSH2 server
 * @name startServer
 * @static
 * @method
 * @param {String} hostKeys
 * @param {Number} port
 */
function startServer(hostKeys, port) {

  // Initialize the SSH server. Upon receiving a connection, handleAttackerConnection function will be called
  let banner = '';
  if (sshServerBannerFile) {
    banner = fs.readFileSync(path.resolve(sshServerBannerFile), 'utf8');
  }

  let server = new ssh2.Server({
    hostKeys: hostKeys,
    ident: sshServerIdentifier, // Identifier sent to the client
    banner,
  }, handleAttackerConnection);

  // Bind SSH server to IP address and port
  server.listen(port, mitmIp, function () { // function called when the server has successfully set up
    infoLog('SSH man-in-the-middle server for ' + containerIp + ' listening on ' + mitmIp + ':' + this.address().port);
  });
}

process.on('disconnect', function () {
  process.exit(); // if parent IPC is disconnected, kill the process
});

/**
 * Handle an incoming attacker connection
 * @name handleAttackerConnection
 * @static
 * @method
 * @param {Object} attacker - SSH2 Client Object
 * @param {Object} info - SSH2 Info Object
 */
function handleAttackerConnection(attacker, info) {

  attacker.on('error', function (err) {
    // If/when an error occurs on this attacker object, then this anonymous function will be called
    if (err.code === 'ECONNRESET' || err.message === 'Handshake failed: no matching key exchange algorithm') {
      return;
    }
    debugLog('[Connection] Client error on ssh server', err);
  });

  // Sanity check
  if (attacker._sock._peername === undefined || attacker._sock._peername === null || info.ip === null) {
    debugLog('[Connection] Socket Error');
    return;
  }

  // Get the IP address of the attacker (the client end of the connection)
  let ipAddress = info.ip;
  debugLog('[Connection] Attacker connected: ' + ipAddress + ' | Client Identification: ' + info.header.identRaw);

  // When attacker exits before he or she has authenticated
  attacker.on('end', attackerEndBeforeAuthenticated);

  // Set a custom key for attacker to keep track of the number of login attempts for this connection
  attacker.numberOfAttempts = 0;

  // Set a custom key for the IP (in case something happens to the socket)
  attacker.ipAddress = ipAddress;

  // Handle Attacker Authentication method. handleAttackerAuthCallback is called when the
  // the function handleAttackerAuth calls it using 'cb(param1, param2, etc...)'
  handleAttackerAuth(attacker, handleAttackerAuthCallback);
}

/**
 * When the attacker closes the connection before he or she has authentication,
 * then this function will be called
 *
 */
function attackerEndBeforeAuthenticated() {
  debugLog('[Connection] Attacker closed the connection');
}

/**
 * Handle authentication from the attacker client
 * @name handleAttackerAuth
 * @static
 * @method
 * @param {Object} attacker - SSH2 Client Object
 * @param {Function} cb - function(err, lxc, ctx, attacker) - lxc is the container channel - ctx is the auth ctx - attacker is the connection
 */
function handleAttackerAuth(attacker, cb) {

  // Binds the 'authentication' event to the attacker object. Now, whenever the attacker tries to authenticate, this
  // anonymous function will be called.
  attacker.on('authentication', function (ctx) {
    debugLog('[Auth] Attacker ' + attacker.ipAddress + ' trying to authenticate with \'' + ctx.method + '\'');

    if (ctx.method === 'password' && ctx.username) {
      // The attacker is trying to authenticate using the 'password' authentication method

      // Logging to student file
      loginAttempts.write(moment().format('YYYY-MM-DD HH:mm:ss.SSS') + delimiter + attacker.ipAddress + delimiter +
        ctx.method + delimiter + ctx.username + delimiter + ctx.password + '\n');

      // ----------- Automatic Access START Block --------------

      // Handle Attempt if automatic access is enabled
      if (autoAccessEnabled && !autoAccessThresholdAchieved) {
        handleAttempt(attacker);
      }

      // If automatic access is enabled and the barrier is down, then compromise the honeypot by
      // adding the user to the container if it does not exist and modifying the password for
      // specified user supplied by the attacker (ctx.username)
      if (autoAccessEnabled && autoAccessThresholdAchieved && ctx.username != '' && ctx.password != '') {
        autoAccessEnabled = false;

        debugLog('[Auto Access] Compromising the honeypot');

        debugLog(`[Auto Access] Adding the following credentials: '${ctx.username}:${ctx.password}'`);

        ctx.username = ctx.username.replace(';', '').replace(`'`, ''); // Preliminary Caution
        ctx.password = ctx.password.replace(';', '').replace(`'`, ''); // Preliminary Caution

        // Add user to the container if it does not exist
        // Not successful if the user tries to do command injection
        // SpawnSync and php script handles command injection
        spawnSync('bash', [ path.join(__dirname, '../lxc/add_user.sh'), containerName, ctx.username ]);

        // Load the credentials
        // Again not successful if the attacker uses command injection
        spawnSync('bash', [ path.join(__dirname, '../lxc/load_credentials.sh'), containerName, ctx.username, ctx.password.replace(/`/g, '') ]);

        debugLog('[Auto Access] Auto-access is now disabled for the remainder of this MITM server instance');
      } else if (autoAccessEnabled && !autoAccessThresholdAchieved) {
        // Barrier has not yet been broken
        cb('Not yet compromised', null, ctx, attacker);
        return;
      }

      // ----------- Automatic Access END Block --------------

      // ----------- START Preliminary Authentication --------------
      // Preliminary authentication to alleviate the load on the container SSH server

      let passwordEntry = getPassEntry(ctx.username);

      //debugLog('[Auth] Password Field on container: ' + passwordEntry);

      if (passwordEntry === null) {
        cb('Invalid credentials - User does not exist', undefined, ctx, attacker);
        return;
      }

      if (passwordEntry === '*' || passwordEntry === '!') {
        cb('Invalid credentials - Container user is disabled', undefined, ctx, attacker);
        return;
      }

      try {
        if (crypt3(ctx.password, passwordEntry) !== passwordEntry) {
          cb('Invalid credentials - Password Authentication Failure', undefined, ctx, attacker);
          return;
        } else if (crypt3(ctx.password, passwordEntry) === passwordEntry) {
          debugLog('[Auth] Valid credentials - Password Authentication');
        }
      } catch(err) {
        // If authentication threw an exception
        debugLog('[Auth] Exception thrown by crypt: ' + err);
      }

      // ----------- END Preliminary Authentication --------------

      // Preliminary Authentication is successful, let's try to login using the attacker's credentials
      // Note: It may still fail because of the settings (/etc/ssh/sshd_config) that are put on the container SSH server
      debugLog('[LXC] Attempting to connect to the honeypot: ' + containerIp);

      connectToLXC({
        host: containerIp,
        port: 22,
        username: ctx.username,
        password: ctx.password
      }, function (err, lxc) { // function called after the login attempt to the container
        if (err) {
          if (err.toString().indexOf('EHOSTUNREACH') !== -1) {
            errorLog('[LXC] Cannot reach the container!');
          } else if (err.toString() === 'Error: All configured authentication methods failed') {
            debugLog('[LXC] Authentication Failed');
          }

          cb(err.toString(), lxc, ctx, attacker);
        }

        cb(err, lxc, ctx, attacker);
      });
    } else if (ctx.method === 'publickey') {
      // The attacker is trying to authenticate using the 'publickey' authentication method

      // Logging to student file
      loginAttempts.write(moment().format('YYYY-MM-DD HH:mm:ss.SSS') + delimiter + attacker.ipAddress + delimiter +
        ctx.method + delimiter + ctx.username + delimiter + ctx.key.data.toString('base64') + '\n');

      // Verify that the public key sent by the attacker matches one of the public keys in the
      // ~/.ssh/authorized_keys. Note: ~ is the home directory of the supplied username
      if (verifyAuthKey(ctx.username, ctx.key.data.toString('base64'))) {

        // Home directory must exist because we were able to successfully verify that the publickey
        let homeDir = getHomeDir(ctx.username);
        let origAuthKeys = getAuthKeys(homeDir);
        let authKeysPath = path.join(containerMountPath, homeDir, '/.ssh/authorized_keys');
        let stats = getFileStat(authKeysPath);

        // Insert our own public key inside ~/.ssh/authorized keys since we don't have the private
        // key that the attacker used (which is normal). We use our private key to now gain
        // access to the honeypot system for the attacker.
        insertAuthKeys(homeDir, DEFAULT_KEYS.PUBLIC);
        connectToLXC({
          host: containerIp,
          port: 22,
          username: ctx.username,
          key: DEFAULT_KEYS.PRIVATE,
        }, function (err, lxc) { // function called after the login attempt to the container
          // Once we have successfully connected, restore the original 'authorized_keys' file
          setAuthKeys(homeDir, origAuthKeys);
          // Set the time back to make it look like we didn't work with this file
          setFileTimes(authKeysPath, stats.atime, stats.mtime);
          cb(err, lxc, ctx, attacker);
        });
      }
      else {
        cb('Publickey authentication failed', undefined, ctx, attacker);
      }
    } else if (ctx.method === 'keyboard-interactive') {
      // Reject keyboard-interactive authentication.
      // This SSH server can simply do 'password' and 'publickey' authentication
      cb('Keyboard-interactive is not supported', undefined, ctx, attacker);
    } else if (ctx.method === 'none') {
      // Clients use this authentication method to determine the available authentication methods on the SSH server
      // since the SSH server will reject the response with the available authentication methods.
      cb('No authentication method provided', undefined, ctx, attacker);
    } else {
      // ??? What is this attacker trying to do?
      cb('Unknown authentication method', undefined, ctx, attacker);
    }
  });
}

/**
 * Used when autoAccessEnabled is enabled. Determines if the attacker is allowed automatic access to the honeypot
 * @param attacker
 */
function handleAttempt(attacker) {
  if (!autoAccessEnabled) {
    return;
  }

  let ipAddress = attacker.ipAddress;
  let previouslySeen = false;

  // See if we have already an entry for this IP
  autoIPs.forEach(function (entry) {
    if (entry.IP === ipAddress) {
      // We have an entry, let's increment attempts
      previouslySeen = entry;
      entry.attempts++;
    }
  });

  // If we have not seen this IP before
  if (!previouslySeen) {
    let randomAllowCalculation = null;

    // Normal Distribution Barrier
    if (autoAccessNormalDistributionMean >= 0) {
      randomAllowCalculation = Math.round(autoRandomNormal());
    }
    // Fixed Number of Attempts Barrier
    else if (autoAccessFixed >= 0) {
      randomAllowCalculation = autoAccessFixed;
    }
    // No way to calculate randomAllow...
    else
    {
      errorLog('[Auto Access] Unknown calculation for randomAllow!');
      randomAllowCalculation = Number.MAX_VALUE;
    }

    // Place it in the queue
    autoIPs.enqueue({
      IP: ipAddress,
      attempts: 0,
      randomAllow: randomAllowCalculation
    });

    // Get the entry from the queue
    autoIPs.forEach(function (entry) {
      if (entry.IP === ipAddress) {
        previouslySeen = entry;
        entry.attempts++;
      }
    });
  }

  // If the number of attempts is greater than or equal to the set threshold for this attacker
  if (previouslySeen.attempts >= previouslySeen.randomAllow) {
    autoAccessThresholdAchieved = true;
  }

  debugLog('[Auto Access] Attacker: ' + ipAddress + ', Threshold: ' + previouslySeen.randomAllow + ', Attempts: ' + previouslySeen.attempts);
}


function handleAttackerAuthCallback(err, lxc, authCtx, attacker) {
  // If an error has occurred with authentication (e.g. Invalid credentials)
  if (err) {
    debugLog('[Auth] Attacker authentication error: ' + err);

    try {
      // The MITM SSH server will reject the credentials with the available authentication methods
      authCtx.reject(['publickey', 'password']);
    } catch (err) {
      if (err.message !== 'No auth in progress') {
        // It's okay, attacker just disconnected
        errorLog('[AUTH] Failed to reject authentication');
      }
    }

    // -------- Attacker Limit Number of Attempts per Connection START ------------

    // If the authentication method was not 'none', then increment the login attempts count
    if (authCtx.method !== 'none') {
      attacker.numberOfAttempts++;
      debugLog('[Auth] Attacker: ' + attacker.ipAddress + ' has so far made ' + attacker.numberOfAttempts +
        ' attempts. Remaining: ' +
        (maxAttemptsPerConnection - attacker.numberOfAttempts) + ' attempts');
    }

    // If the number of attempts for this attacker connection is equal to
    // the maximum number of attempts allowed per connection, then close the connection on the attacker
    if (attacker.numberOfAttempts === maxAttemptsPerConnection) {
      debugLog('[Connection] Max Login Attempts Reached - Closing connection on attacker');
      attacker.end();
    }

    // -------- Attacker Limit Number of Attempts per Connection END ---------------
  } else {
    const attackTimestamp = moment();
    const sessionId = attackTimestamp.format('YYYY_MM_DD_HH_mm_ss_SSS');
    // Log to student file
    logins.write(`${attackTimestamp.format('YYYY-MM-DD HH:mm:ss.SSS')}${delimiter}${attacker.ipAddress}${delimiter}${sessionId}\n`);

    attacker.once('ready', function () { // authenticated user

      // Remove previous event listener for when attacker closed the connection
      attacker.removeListener('end', attackerEndBeforeAuthenticated);

      debugLog('[LXC-Auth] Attacker authenticated and is inside container');

      // make a session screen output stream
      const screenWriteOutputStream = fs.createWriteStream(path.join(loggingAttackerStreams, `${sessionId}.log.gz`));
      const keystrokesOutputStream = fs.createWriteStream(path.join(loggingKeystrokes, `${sessionId}.log`));

      // Make a Gzip handler to automatically compress the file on the fly
      const screenWriteGZIP = zlib.createGzip({
        flush : zlib.constants.Z_FULL_FLUSH
      });
      screenWriteGZIP.pipe(screenWriteOutputStream);

      /*let year = dateTime.getFullYear(), month = ('0' + dateTime.getMonth()).slice(-2),
              date = ('0' + dateTime.getDate()).slice(-2), hour = ('0' + dateTime.getHours()).slice(-2),
              minutes = ('0' + dateTime.getMinutes()).slice(-2), seconds = ('0' + dateTime.getSeconds()).slice(-2),
              milliseconds = dateTime.getMilliseconds();*/

      let credential = null;

      if (authCtx.method === 'password') {
        credential = authCtx.password;
      } else if (authCtx.method === 'publickey') {
        credential = authCtx.key.data.toString('base64');
      }

      const metadata = [
        `Container Name: ${containerName}`,
        `Container IP: ${containerIp}`,
        `Attacker IP: ${attacker.ipAddress}`,
        `Attack Timestamp: ${attackTimestamp.format(`YYYY-MM-DD HH:mm:ss.SSS`)}`,
        `Attacker IP Address: ${attacker.ipAddress}`,
        `Login Method: ${authCtx.method}`,
        `Attacker Username: ${authCtx.username}`,
        `Attacker Password: ${credential}`,
        `Session ID: ${sessionId}`,
        `-------- Attacker Stream Below ---------\n`,
      ];

      screenWriteGZIP.write(metadata.join('\n'));

      attacker.once('session', function (accept) {
        let session = accept();
        if (session) {
          handleAttackerSession(session, lxc, sessionId, screenWriteGZIP, keystrokesOutputStream);
        }
      });
      attacker.on('end', function () {
        const endTimestamp = moment();
        logouts.write(`${endTimestamp.format('YYYY-MM-DD HH:mm:ss.SSS')}${delimiter}${attacker.ipAddress}${delimiter}${sessionId}\n`);
        debugLog('[Connection] Attacker closed connection');
        screenWriteGZIP.write(`-------- Attacker Stream Above ---------\n`);
        screenWriteGZIP.write(`Attack End Timestamp: ${endTimestamp.format(`YYYY-MM-DD HH:mm:ss.SSS`)}\n`);
        lxc.end();
        screenWriteGZIP.end(); // end attacker session screen output write stream
        // Log sign out event
      });
    });
    // Disconnect LXC client when attacker closes window
    authCtx.accept();
  }
}

/************************************************************************************
 * ------------- You should not need to modify anything below -----------------------
 * ------------------------  Proceed with caution -----------------------------------
 ************************************************************************************/


/**
 *
 * @param attacker
 * @param lxc
 * @param sessionId
 * @param screenWriteStream
 * @param keystrokesOutputStream
 */
function handleAttackerSession(attacker, lxc, sessionId, screenWriteStream, keystrokesOutputStream) {
  let attackerStream, rows, cols, term;
  let lxcStream;


  attacker.once('pty', function (accept, reject, info) {
    rows = info.rows;
    cols = info.cols;
    term = info.term;
    accept && accept();
    attacker.on('window-change', function (accept, reject, info) {
      if (attackerStream) {
        attackerStream.rows = info.rows;
        attackerStream.columns = info.cols;
        attackerStream.emit('resize');
        lxcStream.setWindow(info.rows, info.cols);
      }
      accept && accept();
    });
  });

  // Non-interactive mode
  attacker.on('exec', function (accept, reject, info) {
    debugLog('[EXEC] Noninteractive mode attacker command: ' + info.command);
    keystrokesOutputStream.write(`${moment().format('YYYY-MM-DD HH:mm:ss.SSS')} [Noninteractive Mode] ${info.command}\n`);

    const execStatement = 'Noninteractive mode attacker command: ' + info.command + '\n--------- Output Below -------\n';

    screenWriteStream.write(execStatement);

    lxc.exec(info.command, function (err, lxcStream) {
      if (err) {
        return errorLog('lxc exec error', err);
      }
      attackerStream = accept();
      lxcStream.on('data', function (data) {
        screenWriteStream.write(data); // log command results to disk
        attackerStream.write(data);
      });
      lxcStream.on('close', function () {
        attackerStream.end();
      });
    });
  });

  // Interactive mode
  attacker.on('shell', function (accept) {
    lxc.shell({
      rows: rows || 24,
      cols: cols || 80,
      term: term || 'ansi'
    }, function (err, lxcStreamObj) {
      lxcStream = lxcStreamObj;
      lxcStream.isTTY = true;

      debugLog('[SHELL] Opened shell for attacker');
      attackerStream = accept();
      attackerStream.isTTY = true;
      attackerStream.rows = rows || 24;
      attackerStream.columns = cols || 80;
      attackerStream.term = term || 'ansi';
      let keystrokeBuffer = [];
      let attackerStreamCopy = new Stream.PassThrough();
      let reader = readline.createInterface({
        input: attackerStreamCopy,
        terminal: true
      });

      let keystrokeFullBuffer = '';

      reader.on('line', function (line) {
        debugLog('[SHELL] line from reader: ' + line.toString());
        debugLog('[SHELL] Keystroke buffer: ' + keystrokeBuffer);
        keystrokesOutputStream.write(`${moment().format('YYYY-MM-DD HH:mm:ss.SSS')} [Full Line Parsed] ${line.toString()}\n`);
        keystrokeBuffer = []; // reset char array
      });

      lxcStream.on('data', function (data) {
        screenWriteStream.write(data); // write screen to disk
        attackerStream.write(data);
      });
      attackerStream.on('data', function (data) {
        debugLog('[SHELL] Attacker Keystroke: ' + printAscii(data.toString()));
        keystrokeFullBuffer += moment().format('YYYY-MM-DD HH:mm:ss.SSS') + ': ' + printAscii(data.toString()) + '\n';

        lxcStream.write(data);
        // record all char code of keystrokes
        let dataString = data.toString();
        let dataCopy = '';
        const now = moment().format('YYYY-MM-DD HH:mm:ss.SSS');
        for (let i = 0, len = dataString.length; i < len; i++) {
          const charCode = dataString.charCodeAt(i);
          const character = dataString.charAt(i);
          keystrokesOutputStream.write(`${now} [Keystroke] ${printAscii(character)} - ${charCode}\n`);
          keystrokeBuffer.push(charCode);
          if (charCode !== 3) { // 3 is ctrl-c, readline doesn't like ctrl-c
            dataCopy += character;
          }
        }

        // push to stream copy for readline
        attackerStreamCopy.write(dataCopy);
      });

      attackerStream.on('end', function () {
        debugLog('[SHELL] Attacker ended the shell');

        // Keystroke Writing
        screenWriteStream.write('-------- Attacker Keystrokes ----------\n');
        screenWriteStream.write(keystrokeFullBuffer);
        lxcStream.end();
      });

      lxcStream.on('end', function () {
        let position = lxcStreams.indexOf(lxcStream);
        if (position > -1) {
          lxcStreams.splice(position, 1);
          debugLog('[LXC Streams] Removed Stream | Total streams: ' + lxcStreams.length);
        }
        debugLog('[SHELL] Honeypot ended shell');
        attackerStream.end();
      });

      // Keep track of LXC Streams
      lxcStreams.push(lxcStream);
      debugLog('[LXC Streams] New Stream | Total Streams: ' + lxcStreams.length);
    });
  });
}

/************************************************************************************
 * ------------------------------- LXC START Block ----------------------------------
 ************************************************************************************/

/**
 * Connect to a honeypot LXC container
 * @name connectToLXC
 * @static
 * @method
 * @param {Object} opts - {host, port, username, password | key}
 * @param {Function} cb - function(err, lxc)
 */
function connectToLXC(opts, cb) {
  let lxc = new ssh2.Client();

  let connectOptions;
  if (opts.password || opts.password === '') { // password authentication
    connectOptions = {
      host: opts.host,
      port: opts.port,
      username: opts.username,
      password: opts.password,
      readyTimeout: 30000,
    };
  } else if (opts.key) { // key authentication
    connectOptions = {
      host: opts.host,
      port: opts.port,
      username: opts.username,
      privateKey: opts.key
    }
  } else {
    return cb('Invalid authentication method');
  }

  lxc.on('ready', function () { // allow authenticate
    autoAccessEnabled = false; // Attacker is successfully getting inside the container

    return cb(undefined, lxc);
  });
  lxc.on('close', function (err) {
    if (err) {
      errorLog('LXC close error', err);
    }
    debugLog('[LXC] Container\'s OpenSSH server closed connection');
  });
  lxc.on('end', function () {
    debugLog('[LXC] Container\'s OpenSSH server ended connection');
  });
  lxc.on('error', function (err) {
    return cb(err);
  });

  lxc.connect(connectOptions); // connect to the LXC container
}

/************************************************************************************
 * ------------------------------- LXC END Block ------------00----------------------
 ************************************************************************************/


/************************************************************************************
 * ----------------------- Authentication START Block -------------------------------
 ************************************************************************************/

/**
 * Test to see if attacker provided public key is in the destination home directory
 * @static
 * @method
 * @param {String} username
 * @param {String} pubKey
 * @returns {Boolean}
 */
function verifyAuthKey(username, pubKey) {
  let matches = false;
  let targetHomeDir = getHomeDir(username);

  // User's home directory does not exist
  if (targetHomeDir === null || targetHomeDir === '') {
    return false;
  }

  getAuthKeys(targetHomeDir).split('\n').forEach(function (line) {
    let columns = line.split(' ');
    //let alg = columns[0];
    let key = columns[1];
    //let comment = columns[2];
    if (key === pubKey) {
      matches = true;
    }
  });

  return matches;
}

function getHomeDir(username) {
  let passwd = undefined;

  // Try to read the contents of the container's /etc/passwd file
  try {
    passwd = fs.readFileSync(path.join(containerMountPath, '/etc/passwd')).toString();
  } catch (e) {
    if (e.code !== 'ENOENT') {
      errorLog(e);
      return undefined;
    } else {
      passwd = '';
    }
  }

  let targetHomeDir = null;
  passwd.split('\n').forEach(function (line) {
    let columns = line.split(':');
    let user = columns[0];
    let homedir = columns[5];
    if (user === username) {
      targetHomeDir = homedir;
    }
  });

  return targetHomeDir;
}

function getPassEntry(username) {
  let passwd = undefined;

  // Try to read the contents of the container's /etc/passwd file
  try {
    passwd = fs.readFileSync(path.join(containerMountPath, '/etc/shadow')).toString();
  } catch (e) {
    if (e.code !== 'ENOENT') {
      errorLog(e);
      return undefined;
    } else {
      passwd = '';
    }
  }

  let pass = null;
  passwd.split('\n').forEach(function (line) {
    let columns = line.split(':');
    let user = columns[0];
    let userPass = columns[1];
    if (user === username) {
      pass = userPass;
    }
  });

  return pass;
}

function getAuthKeys(homedir) {
  try {
    return fs.readFileSync(path.join(containerMountPath, homedir, '/.ssh/authorized_keys')).toString();
  } catch (e) {
    return '';
  }
}

function setAuthKeys(homedir, authKeys) {
  try {
    fs.writeFileSync(path.join(containerMountPath, homedir, '/.ssh/authorized_keys'), authKeys);
  } catch (e) {
    errorLog(e);
  }
}

function insertAuthKeys(homedir, authKey) {
  try {
    fs.appendFileSync(path.join(containerMountPath, homedir, '/.ssh/authorized_keys'), authKey);
  } catch (e) {
    errorLog(e);
  }
}

function getFileStat(file) {
  try {
    let stat = fs.statSync(file);
    return {
      atime: stat.atime,
      mtime: stat.mtime,
      ctime: stat.ctime
    };
  } catch (e) {
    errorLog(e);
    return {};
  }
}

function setFileTimes(file, atime, mtime) {
  try {
    fs.utimesSync(file, atime, mtime);
  } catch (e) {
    errorLog(e);
  }
}

/************************************************************************************
 * ----------------------- Authentication END Block ---------------------------------
 ************************************************************************************/

// Some housekeeping on exit

process.on('exit', function() {
  housekeeping('exit');
});
process.on('SIGINT', function() {
  housekeeping('SIGINT');
});
process.on('SIGUSR1', function() {
  housekeeping('SIGUSR1');
});
process.on('SIGUSR2', function() {
  housekeeping('SIGUSR2');
});
process.on('SIGTERM', function() {
  housekeeping('SIGTERM');
});
process.on('uncaughtException', function(err) {
  if (err.code === 'EADDRINUSE') {
    debugLog(err.message);
    errorLog('Another MITM instance or another program is already listening on this port');
    cleanup = true;
    process.exit(1);
  }
  housekeeping('UncaughtException', err.message)
});

function housekeeping(type, details = null) {
  if (!cleanup) {
    infoLog(`GOT ${type}, shutting down server...`);
    cleanup = true;
    debugLog('Cleaning up...', false);

    if (details !== null) {
      errorLog('Exception occurred: ', false);
      console.log(details);
    }

    // Cleanup open LXC Streams
    debugLog('Cleaning up LXC Streams: ' + lxcStreams.length);
    lxcStreams.forEach(function(lxcStream) {
      lxcStream.close();
    });
    setTimeout(() => process.exit(), 3000);
  }
}
