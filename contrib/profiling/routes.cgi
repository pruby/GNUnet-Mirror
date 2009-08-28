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
$trialuid = $c->param("trialuid");
$dhtqueryid = $c->param("dhtqueryid");
$querytype = $c->param("querytype");

print <<ENDHTML;
<html>
<head>
<title>Route details for request $dhtqueryid</title>
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
<h2>Route details for request $dhtqueryid</h2>

<br/>

ENDHTML

if ($trialuid eq "")
{
  return 0;
}


print <<ENDHTML;
  <table border="1" align=center>
    <tr>
      <td class="inner"><b>Count</b></td>
      <td class="inner"><b>DHT Query UID</b></td>
      <td class="inner"><b>Query Type</b></td>
      <td class="inner"><b>Hops</b></td>
      <td class="inner"><b>DV Hops</b></td>
      <td><b>Succeeded</b></td>
      <td><b>Node UID</b></td>
      <td class="inner"><b>DHT Key</b></td>
      <td class="inner"><b>From Node</b></td>
      <td class="inner"><b>To Node</b></td>
    </tr>
ENDHTML

my $count = 0;

$rth = $dbh->prepare("select * from routes where trialuid=$trialuid and dhtqueryid=$dhtqueryid and querytype=$querytype");
$rth->execute();
while ($data = $rth->fetchrow_hashref())
{
  my $table_line = 
  "<tr>
    <td class=\"inner\">$count</td>
    <td class=\"inner\">$$data{'dhtqueryid'}</td>
    <td class=\"inner\">$$data{'querytype'}</td>
    <td class=\"inner\">$$data{'hops'}</td>
    <td class=\"inner\">$$data{'dvhops'}</td>
    <td class=\"inner\">$$data{'succeeded'}</td>
    <td class=\"inner\">$$data{'nodeuid'}</td>
    <td class=\"inner\">$$data{'dhtkeyuid'}</td>
    <td class=\"inner\">$$data{'from_node'}</td>
    <td class=\"inner\">$$data{'to_node'}</td>
  </tr>";
  print $table_line . "\n";
  $count++;
  $dhtkey = $$data{'dhtkeyuid'};
}

print("</table>");

print <<ENDHTML;
  <h3>Closest Node(s) to Query Key</h3>
  <table border="1" align=center>
    <tr>
      <td class="inner"><b>DHT Key UID</b></td>
      <td class="inner"><b>Node UID</b></td>
      <td class="inner"><b>Inverse Bit Distance</b></td>
    </tr>
ENDHTML

$rth = $dbh->prepare("select * from dhtkeys where dhtkeyuid=$dhtkey");
$rth->execute();

$location = "";
@locationarr = ();
$trialuid = 0;
while ($data = $rth->fetchrow_hashref())
{
  @tempkeyid = split(//, $$data{'keybits'});
  $numbits = @tempkeyid;
  $location = "";
  for ($i = 0; $i < $numbits; $i++)
  {
    $bits = unpack "B8", $tempkeyid[$i];
    @reversedbits;
    $reversebits = reverse($bits);
    #print "$bits is the bits?\n";
    #print "$reversebits is the bits?\n";
    $location = $location . $reversebits;
  }
  @locationarr = split(//, $location);
  $trialuid = $$data{'trialuid'};
}

$rth = $dbh->prepare("select nodeuid, nodebits from nodes where trialuid=$trialuid");
$rth->execute();

$max = 0;
@maxarr = ();
while ($data = $rth->fetchrow_hashref())
{
  @tempnodeid = split(//, $$data{'nodebits'});
  $numbits = @tempnodeid;

  $location = "";
  for ($i = 0; $i < $numbits; $i++)
  {
    $bits = unpack "B8", $tempnodeid[$i];
    @reversedbits;
    $reversebits = reverse($bits);
    $location = $location . $reversebits;
  }
  @nodelocationarr = split(//, $location);

  $curr_dist = getDistance(\@locationarr, \@nodelocationarr);
  if ($curr_dist > $max)
  {
    @maxarr = ();
    push (@maxarr, $$data{'nodeuid'});
    $max = $curr_dist;
  }
  elsif ($curr_dist == $max)
  {
    push (@maxarr, $$data{'nodeuid'});
  }
}

foreach $uid (@maxarr)
{
print <<ENDHTML;
    <tr>
      <td class="inner"><b>$dhtkey</b></td>
      <td class="inner"><b>$uid</b></td>
      <td class="inner"><b>$max</b></td>
    </tr>
ENDHTML
}

print ("</table>\n");

if (!(-e "/var/www/localhost/htdocs/dht/tmp_graphs/$dhtqueryid-$querytype.png"))
{
  `/var/www/localhost/htdocs/dht/graphRoute.pl $dhtqueryid $querytype`;
}

@associated_gets;
@associated_puts;
@associated_replies;

if ($querytype == 1)
{
  if (!(-e "/var/www/localhost/htdocs/dht/tmp_graphs/$dhtqueryid-3.png"))
  {
    `/var/www/localhost/htdocs/dht/graphRoute.pl $dhtqueryid 3`;
  }

  if (-e "/var/www/localhost/htdocs/dht/tmp_graphs/$dhtqueryid-3.png")
  {
    push (@associated_replies, $dhtqueryid);
  }
  $rth = $dbh->prepare("select * from routes where trialuid=$trialuid and querytype=2 and dhtkeyuid=$dhtkey and hops = 0 and succeeded = 0");
  $rth->execute();
  while ($data = $rth->fetchrow_hashref())
  {
    if (!(-e "/var/www/localhost/htdocs/dht/tmp_graphs/$$data{'dhtqueryid'}-2"))
    {
      `/var/www/localhost/htdocs/dht/graphRoute.pl $$data{'dhtqueryid'} 2`;
    }

    if (-e "/var/www/localhost/htdocs/dht/tmp_graphs/$$data{'dhtqueryid'}-2.png")
    {
      push (@associated_puts, $$data{'dhtqueryid'});
    }
  }
}
elsif ($querytype == 2)
{
  $rth = $dbh->prepare("select * from routes where trialuid=$trialuid and querytype=1 and dhtkeyuid=$dhtkey and hops = 0 and succeeded = 0");
  $rth->execute();
  while ($data = $rth->fetchrow_hashref())
  {
    if (!(-e "/var/www/localhost/htdocs/dht/tmp_graphs/$$data{'queryuid'}-1"))
    {
      `/var/www/localhost/htdocs/dht/graphRoute.pl $$data{'queryuid'} 1`;
    }

    if (-e "/var/www/localhost/htdocs/dht/tmp_graphs/$$data{'queryuid'}-1")
    {
      push (@associated_gets, $$data{'queryuid'});
    }
  }
  
  $rth = $dbh->prepare("select * from routes where trialuid=$trialuid and querytype=3 and dhtkeyuid=$dhtkey and hops = 0 and succeeded = 0");
  $rth->execute();
  while ($data = $rth->fetchrow_hashref())
  {
    if (!(-e "/var/www/localhost/htdocs/dht/tmp_graphs/$$data{'queryuid'}-3"))
    {
      `/var/www/localhost/htdocs/dht/graphRoute.pl $$data{'queryuid'} 3`;
    }
    print "<h3>found associated reply $$data{'queryuid'}</h3>\n";
    if (-e "/var/www/localhost/htdocs/dht/tmp_graphs/$$data{'queryuid'}-3")
    {
      push (@associated_replies, $$data{'queryuid'});
    }
  }
}
elsif ($querytype == 3)
{
  if (!(-e "/var/www/localhost/htdocs/dht/tmp_graphs/$dhtqueryid-1.png"))
  {
    `/var/www/localhost/htdocs/dht/graphRoute.pl $dhtqueryid 1`;
  }
  print "<h3>found associated reply $dhtqueryid</h3>\n";
  if (-e "/var/www/localhost/htdocs/dht/tmp_graphs/$dhtqueryid-1.png")
  {
    push (@associated_gets, $dhtqueryid);
  }
  $rth = $dbh->prepare("select distinct dhtqueryid from routes where trialuid=$trialuid and querytype=2 and dhtkeyuid=$dhtkey and hops = 0 and succeeded = 0");
  $rth->execute();
  while ($data = $rth->fetchrow_hashref())
  {
    if (!(-e "/var/www/localhost/htdocs/dht/tmp_graphs/$$data{'dhtqueryid'}-2.png"))
    {
      `/var/www/localhost/htdocs/dht/graphRoute.pl $$data{'dhtqueryid'} 2`;
    }

    if (-e "/var/www/localhost/htdocs/dht/tmp_graphs/$$data{'dhtqueryid'}-2.png")
    {
      push (@associated_puts, $$data{'dhtqueryid'});
    }
  }
}

print <<ENDHTML;
<table align=center>
  <tr><td class="inner">Graph of $requests{$querytype} query route</td></tr>
  <tr><td><img src="tmp_graphs/$dhtqueryid-$querytype.png" /></td></tr>
</table>
ENDHTML

foreach $graph (@associated_puts)
{
print <<ENDHTML;
<table align=center>
  <tr><td class="inner">Graph of related put query route</td></tr>
  <tr><td><img src="tmp_graphs/$graph-2.png" /></td></tr>
</table>
ENDHTML
}

foreach $graph (@associated_gets)
{
print <<ENDHTML;
<table align=center>
  <tr><td class="inner">Graph of related get query route</td></tr>
  <tr><td><img src="tmp_graphs/$graph-1.png" /></td></tr>
</table>
ENDHTML
}

foreach $graph (@associated_replies)
{
print <<ENDHTML;
<table align=center>
  <tr><td class="inner">Graph of related reply query route</td></tr>
  <tr><td><img src="tmp_graphs/$graph-3.png" /></td></tr>
</table>
ENDHTML
}

sub getCount
{
  my $new_rth = shift;
  $new_rth->execute();
  my @data = $new_rth->fetchrow_array();
  return $data[0];
}

sub getDistance
{
  $locarrkey = shift;
  $locarrnode = shift;
  
  my $keylocsize = @{$locarrkey};
  my $nodelocsize = @{$locarrnode};

  if ($keylocsize != $nodelocsize)
  {
    print "Key location and node location differ in size?!?\n";
    return -1;
  }
  my $matchcount = 0;
  while (@{$locarrkey}[$matchcount] == @{$locarrnode}[$matchcount])
  {
    $matchcount++;
  }
  return $matchcount;
}