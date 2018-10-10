<?php

// Get and escape shell argument
$container 	= $argv[1];
$user		= escapeshellarg($argv[2]);

$cmd = "lxc-attach -n $container -- useradd $user -m -s /bin/bash > /dev/null 2>&1 || true";
exec($cmd, $output, $ret);

exit(0);
?>
