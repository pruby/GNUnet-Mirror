<?php
include("connect.php3");
if (!$connection) {
  echo "<HTML><HEAD><TITLE>GNUnet-testbed: display</TITLE></HEAD><BODY>";
  echo "Database is down. Cannot list available peers.";
  echo "</body></html>";
  die(-1);
}

$printed=0;
$ip=$_SERVER['REMOTE_ADDR'];
$fipa = explode(".", $ip);
$rip = $fipa[0] << 24 + $fipa[1] << 16 + $fipa[2] << 8 + $fipa[3];
$query = "SELECT * FROM peers;";
$result = mysql_query($query, $connection);
if ($result) {
 $num = mysql_numrows($result);

 for ($i=0;$i<$num;$i++) {
   $row = mysql_fetch_array($result);
   // add here: filtering by trusted IP,
   // filtering by date of entry
   $ok=0;
   $trusted = $row["trusted"];
   $tok = strtok($trusted, "@");
   while ($tok) {
     $ipnm = explode("/", $tok);
     $fipa = explode(".", $ipnm[0]);
     // we shift by 23 (and so on) because PHP does not have unsigned ints and going
     // bignum would be overkill.  So instead we just ignore the last bit in the IP,
     // which should hardly give us any mismatches in practice anyway.
     $fip = ($fipa[0] << 23) + ($fipa[1] << 15) + ($fipa[2] << 7) + ($fipa[3] >> 1);
     if (is_int($ipnm[1])) {
       $fnm = 0;
       $ipnm[1]--;
       while ($ipnm[1] > 0) {
	 $fnm = ($fnm >> 1) | 0x80000000;
         $ipnm[1]--;
       }
     } else {
       $fipa = explode(".", $ipnm[1]);
       $fnm = ($fipa[0] << 23) + ($fipa[1] << 15) + ($fipa[2] << 7) + ($fipa[3] >> 1);
     }
     /*printf("<br>IP: %x (%s) have %x/%x (%s/%s)<br>", 
      $rip, $ip, $fip, $fnm, $ipnm[0], $ipnm[1]);*/
     if ( ($rip & $fnm) == ($fip & $fnm) )
       $ok = 1;
     $tok = strtok("@");
   }
   $login = $row["login"];
   if ($ok != 0) {
     printf("add-node %s %s\n", $row["ip"], $row["port"]);
     $printed=1;
   }
   if ( ($ok == 0) && ($login) ) {
     printf("add-ssh-node %s %s %s\n", $login, $row["ip"], $row["port"]);
     $printed=1;
   }
 }
 if ($num == 0) 
   printf("# No peers available at this point.\n");
 else if ($printed == 0)
   printf("# No peers available at this point for %s.\n", $ip);
} else
  printf("# Database error.\n");

?>