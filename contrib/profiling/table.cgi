#!/usr/bin/perl
use DBI;
use DBD::mysql;
use CGI;
require "/var/www/localhost/htdocs/dht/serverConf.pl";
my $c = new CGI;
$c->header;

$dsn = "DBI:mysql:database=$database;host=$hostname;port=$port";
$dbh = DBI->connect($dsn, $user, $password);

$trialuid = $c->param("trialuid");
print <<ENDHTML;
<html>
<head>
ENDHTML
print("<title>Trial $trialuid Details</title>");
print <<ENDHTML;
<style>
td {color:white;font-family:verdana}
a {color:white}
</style>
</head>

<body id="body" bgcolor=green style="text-align:center">
<br/>
<div><font color=white face=verdana size=+3>Trial List</font></div>
<br/>
  <table border="1" align=center>
    <tr>
      <td><b>Trial ID</b></td><td><b># Nodes</b></td><td><b>Topology</b></td><td><b>Start Time</b></td><td><b>End Time</b></td><td><b># Puts</b></td><td><b>#Gets</b></td><td><b>Concurrent Requests</b></td><td><b>Settle Time</b></td><td><b>Total Connections</b></td>
    </tr>

ENDHTML

my $rth = $dbh->prepare("select * from trials where trialuid=$trialuid");
$rth->execute();

while($data = $rth->fetchrow_hashref())
{
  my $table_line = "<tr><td><a href=\"table.cgi?tableuid=$$data{'trialuid'}\">$$data{'trialuid'}</a></td><td>$$data{'numnodes'}</td><td>$$data{'topology'}</td><td>$$data{'starttime'}</td><td>$$data{'endtime'}</td><td>$$data{'puts'}</td><td>$$data{'gets'}</td><td>$$data{'concurrent'}</td><td>$$data{'settle_time'}</td><td>$$data{'totalConnections'}</td></tr>";
  print $table_line . "\n";
}
print("</table>\n");


print("</body>\n</html>\n");
