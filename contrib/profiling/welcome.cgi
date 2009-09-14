#!/usr/bin/perl
use DBD::mysql;
require "/var/www/localhost/htdocs/dht/serverConf.pl";
print "Content-Type: text/html\n\n";

$dsn = "DBI:mysql:database=$database;host=$hostname;port=$port";
$dbh = DBI->connect($dsn, $user, $password);
%topologies = (0 => "Clique", 1 => "Small World", 2 => "Ring", 3 => "2d-Torus", 4 => "Erdos-Renyi", 5 => "InterNAT");
print <<ENDHTML;
<html>
<head>
<title>DHT Testing Trial Page</title>
<style>
td {color:black;font-family:verdana;text-align:center}
a {color:black}
div {color:black;font-family:verdana}
</style>
</head>

<body id="body" bgcolor=beige style="text-align:center">
<br/>
<div><font size=+3>Trial List</font></div>
<br/>
  <table border="1" align=center>
    <tr>
      <td><b>Trial ID</b></td>
      <td><b># Nodes</b></td>
      <td><b>Topology</b></td>
      <td class="inner"><b>Topology<br/>Modifier</b></td>
      <td class="inner"><b>Log<br/>Multiplier</b></td>
      <td><b># Puts</b></td>
      <td><b>#Gets</b></td>
      <td><b>Concurrent<br/>Requests</b></td>
      <td><b>Settle<br/>Time</b></td>
      <td><b>Total<br/>Connections</b></td>
      <td><b>Malicious<br/>Getters</b></td>
      <td><b>Malicious<br/>Putters</b></td>
      <td><b>Malicious<br/>Droppers</b></td>
			<td><b>Max BPS</b></td>
			<td><b>Messages Dropped</b></td>
      <td style="width:150px"><b>Trial<br/>Comment</b></td>
    </tr>

ENDHTML

my $rth = $dbh->prepare("select * from trials where endtime > '0/00/0000' order by trialuid desc");
$rth->execute();

while($data = $rth->fetchrow_hashref())
{
  my $topology_int = $$data{'topology'};
  my $table_line = "<tr>
  <td><a href=\"trial.cgi?trialuid=$$data{'trialuid'}\">$$data{'trialuid'}</a></td>
  <td>$$data{'numnodes'}</td>
  <td>$topologies{$topology_int}</td>
  <td class=\"inner\">" . (int($$data{'topology_modifier'} * 10000) / 10000) . "</td>
  <td class=\"inner\">$$data{'logNMultiplier'}</td>
  <td>$$data{'puts'}</td>
  <td>$$data{'gets'}</td>
  <td>$$data{'concurrent'}</td>
  <td>$$data{'settle_time'}</td>
  <td>$$data{'totalConnections'}</td>
  <td>$$data{'malicious_getters'}</td>
  <td>$$data{'malicious_putters'}</td>
  <td>$$data{'malicious_droppers'}</td>
	<td>$$data{'maxnetbps'}</td>
	<td>$$data{'totalMessagesDropped'}</td>
  <td style=\"width:150px\">$$data{'message'}</td>
  </tr>";
  print $table_line . "\n";
}
print("</table>\n");
print("</body>\n</html>\n");
