<?php
$connection = @mysql_connect("localhost",
			     "testbed",
			     "password");
if ($connection) {
  mysql_select_db("testbedDB",
		  $connection);
  $query = "CREATE TABLE IF NOT EXISTS peers (trusted BLOB, login BLOB, ip BLOB, port BLOB, startup TIMESTAMP)";
  mysql_query($query);
}
?>