#!/usr/bin/perl
use DBD::mysql;
use CGI;
require "/var/www/localhost/htdocs/dht/serverConf.pl";
my $c = new CGI;
$c->header;

$dsn = "DBI:mysql:database=$database;host=$hostname;port=$port";
$dbh = DBI->connect($dsn, $user, $password);
%topologies = (0 => "Clique", 1 => "Small World", 2 => "Ring", 3 => "2d-Torus", 4 => "Erdos-Renyi", 5 => "InterNAT");
$trialuid = $c->param("trialuid");
print <<ENDHTML;
<html>
<head>
<title>Trial $trialuid Details</title>
<style>
td {color:black;font-family:verdana}
a {color:black}
h2 {color:black;font-family:verdana}
td { padding-top: 1px;padding-bottom: 1px;padding-left: 4px;padding-right: 4px;}
td.inner {text-align:center}

</style>
</head>

<body id="body" bgcolor=beige style="text-align:center">
<br/>
<h2>Trial $trialuid Info</h2>
<br/>
  <table border="1" align=center>
    <tr>
      <td><b>Trial ID</b></td>
      <td class="inner"><b># Nodes</b></td>
      <td class="inner"><b>Topology</b></td>
      <td class="inner"><b>Topology<br/>Modifier</b></td>
      <td class="inner"><b>Log<br/>Multiplier</b></td>
      <td><b># Puts</b></td><td><b>#Gets</b></td>
      <td class="inner"><b>Concurrent<br/>Requests</b></td>
      <td class="inner"><b>Settle<br/>Time</b></td>
      <td class="inner"><b>Total<br/>Connections</b></td>
      <td class="inner"><b>Average<br/>Connections</b></td>
      <td class="inner"><b>ln(N)<br/>Multiplier</b></td>
      <td class="inner"><b>Messages<br/>Dropped</b></td>
      <td class="inner"><b>Bytes<br/>Dropped</b></td>
      <td class="inner"><b>Trial<br/>Comment</b></td>
    </tr>

ENDHTML

my $rth = $dbh->prepare("select * from trials where trialuid=$trialuid");
$rth->execute();

while($data = $rth->fetchrow_hashref())
{
  my $topology_int = $$data{'topology'};

  $numNodes = $$data{'numnodes'};
  $topology = $topologies{$topology_int};
  $totalConnections = $$data{'totalConnections'};
  $averageConnections = int(100 * ($$data{'totalConnections'}/$$data{'numnodes'}))/100;
  $logNMultiplier = int(100 * ($averageConnections / log($numNodes)))/100;

  my $table_line = "<tr>
  <td class=\"inner\"><a href=\"trial.cgi?trialuid=$$data{'trialuid'}\">$$data{'trialuid'}</a></td>
  <td class=\"inner\">$$data{'numnodes'}</td>
  <td class=\"inner\">$topologies{$topology_int}</td>
  <td class=\"inner\">$$data{'topology_modifier'}</td>
  <td class=\"inner\">$$data{'logNMultiplier'}</td>
  <td class=\"inner\">$$data{'puts'}</td>
  <td class=\"inner\">$$data{'gets'}</td>
  <td class=\"inner\">$$data{'concurrent'}</td>
  <td class=\"inner\">$$data{'settle_time'}</td>
  <td class=\"inner\">$$data{'totalConnections'}</td>
  <td class=\"inner\">" . int(100 * ($$data{'totalConnections'}/$$data{'numnodes'}))/100 . "</td>
  <td class=\"inner\">" . int(100 * log($$data{'numnodes'}))/100 . "</td>
  <td class=\"inner\">$$data{'totalMessagesDropped'}</td>
  <td class=\"inner\">$$data{'totalBytesDropped'}</td>
  <td class=\"inner\">$$data{'message'}</td>
  </tr>";
  print $table_line . "\n";
}
print("</table>\n");

#Select for number of malicious puts initiated
my $rth = $dbh->prepare("select count(*) from queries where trialuid=$trialuid and querytype = 2 and succeeded = 0 and hops = 0");
$num_malicious_puts = 0;

#Select for number of puts initiated
my $rth = $dbh->prepare("select count(*) from queries where trialuid=$trialuid and querytype = 2 and succeeded = 0 and hops = 0");
$num_puts = getCount($rth);

#Select for number of puts that succeeded
my $rth = $dbh->prepare("select count(distinct dhtkeyuid) from queries where trialuid=$trialuid and querytype = 2 and succeeded = 1");
$num_puts_succeeded = getCount($rth);
$num_puts_failed = $num_puts - $num_puts_succeeded;

if ($num_puts > 0)
{
  $percent_puts_succeeded = int(100 * ($num_puts_succeeded/$num_puts))/100;
}
else
{
  $percent_puts_succeeded = 0;
}

#Select for all puts that succeeded
my $rth = $dbh->prepare("select dhtkeyuid from queries where trialuid=$trialuid and querytype = 2 and succeeded = 1");
$rth->execute();

%put_replica_hash = {};
$put_replica_average = 0;
$put_replicas = 0;
while($data = $rth->fetchrow_hashref())
{
  if (exists $put_replica_hash{$$data{'dhtkeyuid'}})
  {
    $put_replica_hash{$$data{'dhtkeyuid'}} = $put_replica_hash{$$data{'dhtkeyuid'}} + 1;
  }
  else
  {
    $put_replica_hash{$$data{'dhtkeyuid'}} = 1;
  }
}

foreach $key (keys(%put_replica_hash))
{
  $put_replicas += $put_replica_hash{$key};
}
$put_replicas_average = int(($put_replicas/$num_puts_succeeded) * 100) / 100;

#Select for number of gets initiated
my $rth = $dbh->prepare("select count(*) from queries where trialuid=$trialuid and querytype = 1 and succeeded = 0 and hops = 0 and dhtkeyuid <> 0");
$num_gets = getCount($rth);


#Select for number of gets that hit data
my $rth = $dbh->prepare("select count(distinct dhtqueryid) from queries where trialuid=$trialuid and querytype = 1 and succeeded = 1");
$num_gets_succeeded = getCount($rth);
$num_gets_failed = $num_gets - $num_gets_succeeded;


if ($num_gets > 0)
{
  $percent_gets_succeeded = int(100 * ($num_gets_succeeded/$num_gets))/100;
}
else
{
  $percent_gets_succeeded = 0;
}

#Select for all gets that succeeded
my $rth = $dbh->prepare("select dhtqueryid from queries where trialuid=$trialuid and querytype = 1 and succeeded = 1");
$rth->execute();

%get_replica_hash = {};
$get_replica_average = 0;
$get_replicas = 0;
while($data = $rth->fetchrow_hashref())
{
  if (exists $get_replica_hash{$$data{'dhtqueryid'}})
  {
    $get_replica_hash{$$data{'dhtqueryid'}} = $get_replica_hash{$$data{'dhtqueryid'}} + 1;
  }
  else
  {
    $get_replica_hash{$$data{'dhtqueryid'}} = 1;
  }
}

foreach $key (keys(%get_replica_hash))
{
  $get_replicas += $get_replica_hash{$key};
}
$get_replicas_average = int(($get_replicas/$num_gets_succeeded) * 100) / 100;


#Select for number of malicious gets initiated
my $rth = $dbh->prepare("select count(*) from queries where trialuid=$trialuid and querytype = 1 and succeeded = 0 and hops = 0 and dhtkeyuid = 0");
$num_malicious_gets = getCount($rth);



#Select for number of replies started
my $rth = $dbh->prepare("SELECT count(distinct dhtqueryid) FROM `queries` where trialuid = $trialuid and querytype = 3 and succeeded = 0 and hops = 0");
$num_replies = getCount($rth);

#Select for number of replies that succeeded
my $rth = $dbh->prepare("SELECT count(distinct dhtqueryid) FROM `queries` where trialuid = $trialuid and querytype = 3 and succeeded = 1");
$num_replies_succeeded = getCount($rth);
$num_replies_failed = $num_replies - $num_replies_succeeded;

if ($num_replies > 0)
{
    $percent_replies_succeeded = int(100 * ($num_replies_succeeded / $num_replies))/100;
}
else
{
  $percent_replies_succeeded = 0;
}


print <<ENDHTML;
<h2>Trial Statistics</h2>
<table align=center border=1 padding=1>
  <tr>
    <td><b>Stat</b></td>
    <td><b>Attempts</b></td>
    <td><b>Successful</b></td>
    <td><b>Failed</b></td>
    <td class="inner"><b>Success Rate</b></td>
    <td><b>Average</br>Replicas</b></td>
  </tr>
  <tr>
    <td><b>Items Inserted</b></td>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=2">$num_puts</a></td>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=2&succeeded=1">$num_puts_succeeded</a></td>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=2&succeeded=0">$num_puts_failed</a></td>
    <td class="inner">$percent_puts_succeeded</td>
    <td class="inner">$put_replicas_average</td>
  </tr>
  <tr>
    <td><b>Items Searched</b></td>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=1">$num_gets</a></td>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=1&succeeded=1">$num_gets_succeeded</a></td>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=1&succeeded=0">$num_gets_failed</a></td>
    <td class="inner">$percent_gets_succeeded</td>
    <td class="inner">$get_replicas_average</td>
  </tr>
  <tr>
    <td><b>Replies</b></td>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=3">$num_replies</a></td>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=3&succeeded=1">$num_replies_succeeded</a></td>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=3&succeeded=0">$num_replies_failed</a></td>
    <td class="inner">$percent_replies_succeeded</td>
  </tr>
</table>
ENDHTML

print <<ENDHTML;
<h2>Malicious Message Statistics</h2>
<table align=center border=1 padding=1>
  <tr>
    <td><b>Malicious Gets</b></td>
    <td><b>Malicious Puts</b></td>
  </tr>
  <tr>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=2&succeeded=1">$num_malicious_gets</a></td>
    <td class="inner"><a href="queries.cgi?trialuid=$trialuid&querytype=2&succeeded=0">$num_malicious_puts</a></td>
  </tr>
</table>
ENDHTML

#Select for number of gets initiated
my $rth = $dbh->prepare("select * from queries where trialuid=$trialuid and querytype = 2 and succeeded = 0 and hops = 0");
$rth->execute();

my $rth = $dbh->prepare("SELECT * FROM `queries` where trialuid = $trialuid and querytype = 3 and succeeded = 0 and hops = 0");
$rth->execute();

#Select for average hopcount for successful gets
my $rth = $dbh->prepare("SELECT avg(hops) FROM `queries` where trialuid = $trialuid and querytype = 1 and succeeded = 1");
$avg_get_hops = int(getCount($rth) * 100)/100;

#Select for average hopcount for successful puts
my $rth = $dbh->prepare("SELECT avg(hops) FROM `queries` where trialuid = $trialuid and querytype = 2 and succeeded = 1");
$avg_put_hops = int(getCount($rth) * 100)/100;

#Select for average hopcount for successful replies
my $rth = $dbh->prepare("SELECT avg(hops) FROM `queries` where trialuid = $trialuid and querytype = 3 and succeeded = 1");
$avg_reply_hops = int(getCount($rth) * 100)/100;

#Select for max hopcount for successful gets
my $rth = $dbh->prepare("SELECT max(hops) FROM `queries` where trialuid = $trialuid and querytype = 1 and succeeded = 1");
$max_get_hops = getCount($rth);

#Select for max hopcount for successful puts
my $rth = $dbh->prepare("SELECT max(hops) FROM `queries` where trialuid = $trialuid and querytype = 2 and succeeded = 1");
$max_put_hops = getCount($rth);

#Select for max hopcount for successful replies
my $rth = $dbh->prepare("SELECT max(hops) FROM `queries` where trialuid = $trialuid and querytype = 3 and succeeded = 1");
$max_reply_hops = getCount($rth);

print <<ENDHTML;
<h2>Efficiency Statistics</h2>
<table align=center border=1>
<tr>
<td><b>Stat</b></td><td class="inner"><b>Average Hops<br/>(successful)</b></td><td class="inner"><b>Max hops<br/>(successful)</b></td>
</tr>
<tr>
<td><b>Items Inserted</b></td><td class="inner">$avg_put_hops</td><td class="inner">$max_put_hops</td>
</tr>
<tr>
<td><b>Items Searched</b></td><td class="inner">$avg_get_hops</td><td class="inner">$max_get_hops</td>
</tr>
<tr>
<td><b>Replies</b></td><td class="inner">$avg_reply_hops</td><td class="inner">$max_reply_hops</td>
</tr>
</table>
ENDHTML

print "<h3>Latex</h3>\n";
my $topology_int = $$data{'topology'};
print "&amp; $topology &amp; $numNodes &amp; $averageConnections ($logNMultiplier lnN) &amp; $percent_puts_succeeded &amp; $percent_gets_succeeded &amp; $percent_replies_succeeded &amp; $avg_put_hops &amp; $avg_get_hops &amp; $avg_reply_hops \\\\\n";

print("</body>\n</html>\n");


sub getCount
{
  my $new_rth = shift;
  $new_rth->execute();
  my @data = $new_rth->fetchrow_array();
  return $data[0];
}