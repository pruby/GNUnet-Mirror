#!/usr/bin/perl
use DBD::mysql;
use CGI;
require "/var/www/localhost/htdocs/dht/serverConf.pl";
my $c = new CGI;
$c->header;

$dsn = "DBI:mysql:database=$database;host=$hostname;port=$port";
$dbh = DBI->connect($dsn, $user, $password);
%topologies = (0 => "Clique", 1 => "Small World", 2 => "Ring", 3 => "2d-Torus", 4 => "Erdos-Renyi", 5 => "InterNAT");
%requests = (1 => "GET", 2 => "PUT", 3 => "REPLY", "" => "ALL");
%success = ("" => "All", 1 => "Successful", 0 => "Failed");
%boolean = (0 => "No", 1 => "Yes");
$trialuid = $c->param("trialuid");
$querytype = $c->param("querytype");
$succeeded = $c->param("succeeded");
print <<ENDHTML;
<html>
<head>
<title>$success{$succeeded} $requests{$querytype} details for trial $trialuid</title>
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
<h2>$success{$succeeded} $requests{$querytype} details for <a href=\"trial.cgi?trialuid=$trialuid\">trial $trialuid</a></h2>

<br/>

ENDHTML

if ($trialuid eq "")
{
  return 0;
}
if (($querytype != 1) && ($querytype != 2) && ($querytype != 3))
{
  $querytype = "";
}
@queryuids = ();
@dhtqueryids = ();
@querytypes = ();
@hops = ();
@successes = ();
@nodeuids = ();
@dhtkeyuids = ();

if ($succeeded eq "")
{
  $succeeded = 42;
}
if ($querytype eq "")
{
  $rth = $dbh->prepare("select * from queries where trialuid=$trialuid");
  $rth->execute();
  while ($data = $rth->fetchrow_hashref())
  {
    push (@queryuids, $$data{'queryuid'});
    push (@dhtqueryids, $$data{'dhtqueryid'});
    push (@querytypes, $$data{'querytype'});
    push (@hops, $$data{'hops'});
    push (@successes, $$data{'succeeded'});
    push (@nodeuids, $$data{'nodeuid'});
    push (@dhtkeyuids, $$data{'dhtkeyuid'});
  }
}
elsif (($succeeded == 1) || ($succeeded == 0))
{
  $rth = $dbh->prepare("select * from queries where trialuid=$trialuid and querytype=$querytype order by dhtkeyuid");
  $rth->execute();
  
  $rthfailed = $dbh->prepare("select * from queries where trialuid=$trialuid and querytype=$querytype and succeeded=0 and hops=0 order by dhtkeyuid");
  $rthfailed->execute();

  $rthkeys = $dbh->prepare("select distinct dhtkeyuid from queries where trialuid=$trialuid and querytype=$querytype and succeeded=1 order by dhtkeyuid");
  $rthkeys->execute();
  while ($keydata = $rthkeys->fetchrow_hashref())
  {
    push (@successful_dhtkeyuids, $$keydata{'dhtkeyuid'});
  }
  #print ("<h3>size of successful_dhtkeyuids is " . @successful_dhtkeyuids . "</h3>\n");
  while ($data = $rth->fetchrow_hashref())
  {
    if ((($succeeded == 1) && ($$data{'succeeded'} == 1)) || (($succeeded == 0) && (!(inArr(\@successful_dhtkeyuids, $$data{'dhtkeyuid'})))))
    {
      push (@queryuids, $$data{'queryuid'});
      push (@dhtqueryids, $$data{'dhtqueryid'});
      push (@querytypes, $$data{'querytype'});
      push (@hops, $$data{'hops'});
      push (@successes, $$data{'succeeded'});
      push (@nodeuids, $$data{'nodeuid'});
      push (@dhtkeyuids, $$data{'dhtkeyuid'});
    }
  }
}
else
{
  $rth = $dbh->prepare("select * from queries where trialuid=$trialuid and querytype=$querytype order by dhtkeyuid");
  $rth->execute();
  while ($data = $rth->fetchrow_hashref())
  {
    push (@queryuids, $$data{'queryuid'});
    push (@dhtqueryids, $$data{'dhtqueryid'});
    push (@querytypes, $$data{'querytype'});
    push (@hops, $$data{'hops'});
    push (@successes, $$data{'succeeded'});
    push (@nodeuids, $$data{'nodeuid'});
    push (@dhtkeyuids, $$data{'dhtkeyuid'});
  }
}

print <<ENDHTML;
  <table border="1" align=center>
    <tr>
      <td class="inner"><b>Count</b></td><td class="inner"><b>Queryuid</b></td><td class="inner"><b>DHT Query UID</b></td><td class="inner"><b>Query Type</b></td><td class="inner"><b>Hops</b></td><td><b>Succeeded</b></td><td><b>Node UID</b></td><td class="inner"><b>DHT Key</b></td>
    </tr>
ENDHTML

my $count = 0;
foreach $datum (@queryuids)
{
  my $table_line = 
  "<tr>
    <td class=\"inner\">$count</td>
    <td class=\"inner\"><a href=\"routes.cgi?trialuid=$trialuid&dhtqueryid=$queryuids[$count]&querytype=$querytypes[$count]\">$queryuids[$count]</a></td>
    <td class=\"inner\"><a href=\"routes.cgi?trialuid=$trialuid&dhtqueryid=$dhtqueryids[$count]&querytype=$querytypes[$count]\">$dhtqueryids[$count]</a></td>
    <td class=\"inner\">$requests{$querytypes[$count]}</td>
    <td class=\"inner\">$hops[$count]</td>
    <td class=\"inner\">$boolean{$successes[$count]}</td>
    <td class=\"inner\">$nodeuids[$count]</td>
    <td class=\"inner\">$dhtkeyuids[$count]</td>
  </tr>";
  print $table_line . "\n";
  $count++;
}

print("</table>");

sub getCount
{
  my $new_rth = shift;
  $new_rth->execute();
  my @data = $new_rth->fetchrow_array();
  return $data[0];
}

sub inArr
{
  my $array_ref = shift;
  my $value = shift;

  foreach $item (@{$array_ref})
  {
    if ($item eq $value)
    {
      return 1;
    }
  }
  return 0;
}