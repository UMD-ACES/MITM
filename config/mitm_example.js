'use strict';

module.exports = {
    local: false,
    debug : true,
    logToInstructor: {
        enabled: true,
        host: '172.30.124.11',
        user: 'students',
        password: 'ebJAHqWx.d?&Zh*qX|r*{X+k6vMb',
        database: 'ssh_mitm',
        connectionLimit : 5
    },
    container : {
        mountPath : '/var/lib/lxc/'
    },
    logging : {
        streamOutput : '/root/data/attacker_sessions',
        loginAttempts : '/root/data/login_attempts',
        logins : '/root/data/logins'
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

    }
};
