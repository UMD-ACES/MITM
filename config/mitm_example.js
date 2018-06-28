'use strict';

module.exports = {
    local: false,
    debug : true,
    logToInstructor: {
        enabled: false,
        host: 'X.X.X.X',
        user: 'user',
        password: 'pass',
        database: 'db',
        connectionLimit : 5
    },
    attacker : {
        streamOutput : '/root/attacker_sessions'
    },
    server : {
        maxAttemptsPerConnection: 6,
        listenIP : '0.0.0.0',
        identifier : 'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2',
    },
    container : {
        mountPath : '/media/'
    },
    autoAccess : {
        enabled: true,
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
