<?php
global $trusted;
include("connect.php3");
if (!$connection) {
  echo "<HTML><HEAD><TITLE>GNUnet-testbed registration: startup</TITLE></HEAD><BODY>";
  echo "Database is down. Cannot register peers.";
  echo "</body></html>";
  die(-1);
}

$query = "INSERT INTO peers VALUES(\"$trusted\", \"$port\", \"$secure\", \"" . $_SERVER['REMOTE_ADDR'] . "\", NOW());";
mysql_query($query, $connection);

?>