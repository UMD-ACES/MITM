'use strict';

//https://stackoverflow.com/questions/6274339/how-can-i-shuffle-an-array
function shuffle(a) {
   var j, x, i;
   for (i = a.length - 1; i > 0; i--) {
        j = Math.floor(Math.random() * (i + 1));
        x = a[i];
        a[i] = a[j];
        a[j] = x;
    }
    return a;
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const init_scrambler = (scrambler) => {
    let len = alphabet.length;
    if (len % 2 == 0) {

        let scrambled_alph = shuffle(Array.from(alphabet));
        for (let i = 0; i < len; i += 2) {

            scrambler[scrambled_alph[i]] = scrambled_alph[i + 1];
            scrambler[scrambled_alph[i].toLowerCase()] = scrambled_alph[i + 1].toLowerCase();
            scrambler[scrambled_alph[i + 1]] = scrambled_alph[i];
            scrambler[scrambled_alph[i + 1].toLowerCase()] = scrambled_alph[i].toLowerCase();
        }
    }
    else {

    	console.log("error. cannot fully pair scramble alphabet with odd cardinality");
    }
}

module.exports = {
    local: false,
    debug : true,
    logToInstructor: {
        enabled: false,
        host: '172.30.125.124',
        user: 'students',
        password: 'ebJAHqWx.d?&Zh*qX|r*{X+k6vMb',
        database: 'ssh_mitm_f19',
        connectionLimit : 5
    },
    container : {
        mountPath: {
            prefix: '/var/lib/lxc/',
            suffix: 'rootfs'
        },
    },
    logging : {
        streamOutput : '/root/MITM_data/sessions',
        loginAttempts : '/root/MITM_data/login_attempts',
        logins : '/root/MITM_data/logins'
    },
    server : {
        maxAttemptsPerConnection: 6,
        listenIP : '0.0.0.0',
        identifier : 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2',
        banner : ''
    },
    autoAccess : {
        enabled: false,
        cacheSize : 5000,
        barrier: {
            normalDist: {
                enabled: false,
                mean: 6,
                standardDeviation: 1,
            },
            fixed: {
                enabled: true,
                attempts: 3,
            }
        }

    },
    init_scrambler : init_scrambler
};
