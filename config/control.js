'use strict';

const init_scrambler = (scrambler) => {
}

module.exports = {
    local: false,
    debug : false,
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
                attempts: 1,
            }
        }

    },
    init_scrambler : init_scrambler
};
