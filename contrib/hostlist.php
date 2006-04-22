<?php
// Requires PHP >= 4.3.0
// Author: "Krasko Oleksandr" <0m3r.mail@gmail.com>
// Minor improvements by Christian Grothoff <christian@grothoff.org>
header("Content-Type: application/octet-stream\r\n\r\n");
$extmas = array('6','8','12','17','23','25');
$path = '/var/lib/GNUnet/data/hosts/'; // adjust as necessary
$dir = opendir($path);
if (! $dir)
  die("Cannot open directory $path.\n");
$mas = array();
while ($fname = readdir($dir)) {
  $fn = $path . '/' . $fname;
  if (is_file($fn)) {
    $dpo = strpos($fname, '.') + 1;
    $len = strlen($fname);
    if (in_array(substr($fname, $dpo - $len), $extmas)) 
      $mas[] = $fn;
  }
}
shuffle($mas); // randomize order
foreach ($mas as $val) 
  echo file_get_contents($val);
?>
