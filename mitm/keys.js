let fs = require('fs'),
    path = require('path'),
    config = require('../config/mitm');

let keyFilename = 'defaultKey';

let keyLocations = [
    '/etc/ssh/ssh_host_ecdsa_key',
    '/etc/ssh/ssh_host_rsa_key',
    '/etc/ssh/ssh_host_dsa_key',
   // '/etc/ssh/ssh_host_ed25519_key' - Unsupported Format
];


function readDefaultKeys() {
    return readKeys(keyFilename);
}

function readKeys(filename) {
    return fs.readFileSync(path.resolve(__dirname, filename));
}

function readCTKeys(ctID) {
  let keys = [];

  for(let i = 0; i < keyLocations.length; i++)
  {
      keys[i] = readKeys(config.container.mountPath + ctID + keyLocations[i]);
  }

  return keys;
}

/**
 * Loads the private and public keys
 * @name loadKeys
 * @static
 * @method
 * @param {String} ctID - the name of the target container
 * @param {Function} cb - function(privateKey, publicKey)
 * @throws {Error} - if key generation fails
 */
function loadKeys(ctID, cb) {
  let keys = [];

  try {
      keys = readCTKeys(ctID);
  } catch (e) {
      console.log("CRITICAL WARNING: Could not read the keys from the container!");
      keys = [readDefaultKeys()];
  }
  return cb(keys);
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
  if (!fs.existsSync(path.resolve(pathname))) {
    fs.mkdirSync(path.resolve(pathname), '775');
  }
}

module.exports = {
  loadKeys : loadKeys,
  makeOutputFolder : makeOutputFolder
};
