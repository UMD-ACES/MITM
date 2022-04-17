let fs = require('fs'),
  path = require('path');

let keyFilename = 'defaultKey';

let keyLocations = [
  'etc/ssh/ssh_host_ecdsa_key',
  'etc/ssh/ssh_host_rsa_key',
  // 'etc/ssh/ssh_host_dsa_key', -- Not default anymore
  // '/etc/ssh/ssh_host_ed25519_key' - Unsupported Format
];


function readDefaultKeys() {
  return readKeys(keyFilename);
}

function readKeys(filename) {
  const key = fs.readFileSync(filename);

  return key;
}

function readCTKeys(mountPath, ctID) {
  let keys = [];

  for (let i = 0; i < keyLocations.length; i++) {
    const targetPath = path.join(mountPath, keyLocations[i]);
    keys[i] = readKeys(targetPath);
  }

  return keys;
}

/**
 * Loads the private and public keys
 * @name loadKeys
 * @static
 * @method
 * @param {String} mountPath - Container mount path
 * @param {String} ctID - the name of the target container
 * @throws {Error} - if key generation fails
 */
function loadKeys(mountPath, ctID) {
  let keys = [];

  try {
    keys = readCTKeys(mountPath, ctID);
  } catch (e) {
    console.log(e);
    if (e.code === 'EACCES') {
      console.log('[ERROR] Could not read the keys from the container! Permission denied, are you the root user?');
    } else {
      console.log('[ERROR] Could not read the keys from the container! Is the container mounted/running and is openssh-server installed?');
    }
    process.exit(1);
  }
  return keys;
}

/**
 * Makes the output folder for the attacker session screens
 * @name makeOutputFolder
 * @static
 * @method
 * @param {String} pathname - path of the output folder
 * @throws {Error} - if mkdirSync fails
 */
function makeOutputFolder(pathname) {
  if (!fs.existsSync(pathname)) {
    fs.mkdirSync(pathname, { recursive: true });
  }
}

module.exports = {
  loadKeys : loadKeys,
  makeOutputFolder : makeOutputFolder
};
