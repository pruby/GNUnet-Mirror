<?php
include("connect.php3");
if (!$connection) {
  echo "<HTML><HEAD><TITLE>GNUnet-testbed registration: shutdown</TITLE></HEAD><BODY>";
  echo "Database is down. Cannot unregister peer.";
  echo "</body></html>";
  die(-1);
}

$query = "DELETE FROM peers WHERE ip=\"" . $_SERVER['REMOTE_ADDR'] . "\";";
mysql_query($query, $connection);

?>
