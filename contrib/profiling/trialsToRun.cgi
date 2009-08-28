#!/usr/bin/perl
use DBD::mysql;
use CGI;
require "/var/www/localhost/htdocs/dht/serverConf.pl";
my $c = new CGI;
$c->header;

$dsn = "DBI:mysql:database=$database;host=$hostname;port=$port";
$dbh = DBI->connect($dsn, $user, $password);
%topologies = (0 => "Clique", 1 => "Small World", 2 => "Ring", 3 => "2d-Torus", 4 => "Erdos-Renyi", 5 => "InterNAT");
$numnodes = 0;
$numnodes = $c->param("numnodes");
$errors = "";
$sqlinsert = "";
if ($numnodes > 0)
{
  my $puts = $c->param("puts");
  my $gets = $c->param("gets");
  my $topology_modifier = $c->param("topology_modifier");
  my $logNMultiplier = $c->param("logNMultiplier");
  my $topology = $c->param("topology");
  my $concurrent = $c->param("concurrent");
  my $settle_time = $c->param("settle_time");
  my $malicious_droppers = $c->param("malicious_droppers");
  my $malicious_getters = $c->param("malicious_getters");
  my $malicious_putters = $c->param("malicious_putters");
  my $malicious_get_frequency = $c->param("malicious_get_frequency");
  my $malicious_put_frequency = $c->param("malicious_put_frequency");
  my $message = $c->param("message");
  $sqlinsert = "insert into trialsToRun (numnodes, concurrent, settle_time, puts, gets, topology, topology_modifier, logNMultiplier, malicious_getters, malicious_get_frequency, malicious_putters, malicious_put_frequency, malicious_droppers, message) values (\'$numnodes\', \'$concurrent\', \'$settle_time\', \'$puts\', \'$gets\', \'$topology\', \'$topology_modifier\', \'$logNMultiplier\', \'$malicious_getters\', \'$malicious_get_frequency\', \'$malicious_putters\', \'$malicious_put_frequency\', \'$malicious_droppers\', \'$message\')";
  my $rth = $dbh->prepare($sqlinsert);
  $rth->execute();

  $errors = $dbh->errstr() . $rth->errstr();
}
print <<ENDHTML;
<html>
<head>
<title>Trial Scheduler</title>
<style>
td {color:black;font-family:verdana}
a {color:black}
h2 {color:black;font-family:verdana}
td { padding-top: 1px;padding-bottom: 1px;padding-left: 4px;padding-right: 4px; text-align:center}
td.inner {text-align:center}

</style>
</head>

<body id="body" bgcolor=beige style="text-align:center">
<br/>
<h2>Trial $numnodes Info</h2>
<h4>$errors</h4>
<br/>
  <table border="1" align=center>
    <tr>
      <td><b>Trial ID</b></td>
      <td><b># Nodes</b></td>
      <td><b>Topology</b></td>
      <td><b>Modifier</b></td>
      <td><b>LogN Multiplier</b></td>
      <td><b># Puts</b></td>
      <td><b>#Gets</b></td>
      <td><b>Concurrency</b></td>
      <td><b>Settle</b></td>
      <td><b>Malicious Getters</b></td>
      <td><b>Malicious Get Frequency</b></td>
      <td><b>Malicious Putters</b></td>
      <td><b>Malicious Put Frequency</b></td>
      <td><b>Malicious Droppers</b></td>
      <td><b>Message</b></td>
    </tr>

ENDHTML

my $rth = $dbh->prepare("select * from trialsToRun order by trialuid");
$rth->execute();

while($data = $rth->fetchrow_hashref())
{
  my $table_line = "<tr><td class=\"inner\">$$data{'trialuid'}</td><td class=\"inner\">$$data{'numnodes'}</td>
  <td class=\"inner\">$topologies{$$data{'topology'}}</td>
  <td class=\"inner\">$$data{'topology_modifier'}</td>
  <td class=\"inner\">$$data{'logNMultiplier'}</td>
  <td class=\"inner\">$$data{'puts'}</td>
  <td>$$data{'gets'}</td>
  <td class=\"inner\">$$data{'concurrent'}</td>
  <td class=\"inner\">$$data{'settle_time'}</td>
  <td class=\"inner\">$$data{'malicious_getters'}</td>
  <td class=\"inner\">$$data{'malicious_get_frequency'}</td>
  <td class=\"inner\">$$data{'malicious_putters'}</td>
  <td class=\"inner\">$$data{'malicious_put_frequency'}</td>
  <td class=\"inner\">$$data{'malicious_droppers'}</td>
  <td class=\"inner\">$$data{'message'}</td></tr>";
  print $table_line . "\n";
}
print <<ENDHTML;
<form name="add_row" type=get>
    <tr>
      <td>----</td><td><input size=3 type="text" name="numnodes"/></td><td><select name="topology">
ENDHTML
  foreach $key (keys(%topologies))
  { 
    if ($key == 1)
    {
      print("<option value=$key selected>$topologies{$key}</option>");
    }
    else
    {
      print("<option value=$key>$topologies{$key}</option>");
    }
  }
print <<ENDHTML;
      </select></td>
      <td><input size=4 type="text" name="topology_modifier"</td>
      <td><input size=4 type="text" name="logNMultiplier"</td>
      <td><input size=5 type="text" name="puts" /></td>
      <td><input size=5 type="text" name="gets"/></td>
      <td><input size=3 type="text" name="concurrent" /></td>
      <td><input size=3 type="text" name="settle_time"/></td>
      <td><input size=3 type="text" name="malicious_getters"/></td>
      <td><input size=3 type="text" name="malicious_get_frequency"/></td>
      <td><input size=3 type="text" name="malicious_putters"/></td>
      <td><input size=3 type="text" name="malicious_put_frequency"/></td>
      <td><input size=3 type="text" name="malicious_droppers"/></td>
      <td><input type="text" name="message"/></td>
    </tr>
    <tr><td colspan=14 class="inner"><input type="submit" value="Add Trial" /></td></tr>
</form>
ENDHTML
print("</table>\n");
print("</body>\n</html>\n");