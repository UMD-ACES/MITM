<?php

// Get and escape shell argument
$container 	= $argv[1];
$user		= escapeshellarg($argv[2]);

$password  	= escapeshellarg($argv[3]);
$password 	= str_replace('`', '', $password);

$cmd = "lxc-attach -n $container -- usermod -p `openssl passwd $password` $user";
echo $cmd.PHP_EOL;
exec($cmd, $output, $ret);

exit(0);
?>
