:
# cvs-exp.pl: a global-picture chronological "cvs log" postprocessor
# author: Sitaram Iyer <ssiyer@cs.rice.edu> 11jan00, one afternoon's work
# Copyright (C) 2000 Rice University
# available at http://www.cs.rice.edu/~ssiyer/code/cvs-exp/
#
# cvs-exp.pl, a parody on the "cvs log" command, is a way of chronologically
# tracking events in a cvs repository, when you're lost among lots of
# branches and tags and little idea of what's going on.
# 
# Usage:
#     cvs-exp.pl [opts] <arguments to cvs log>
# or  cvs log >file; cvs-exp.pl [opts] <file
# where opts:
#    --nolog		don't do the log; only do the tree at the end
#    --notree		vice versa - the default is to print both.
#    --nofiles		don't list files in the log
#    --help		when all else fails
#
# "cvs log" is reasonably good for tracking changes to a single file, but
# for an entire project with lots of branches and tags, it provides _no_
# idea of what's happening on the whole. This cvs-exp.pl works on the output
# of cvs log and arranges events chronologically, merging entries as needed.
# by keeping track of lists of files and revisions, it figures when in the
# sequence of events were various tags and branches created. It prints out a
# cute-looking tree at the end to summarize activity in the repository.

# so two reasons for writing this:
#  * I managed a CVS repository for a tolerably largeish project recently,
#    and had lots of trouble keeping up with the overall state of the
#    project, especially when people kept making mistakes of committing to
#    the wrong branches etc. This would've proved quite useful then.
#  * I like writing _long_ cvs commit descriptions, so a significant part of
#    documentation in my code happens to be scattered among a gazillion
#    files in a CVS repository, and I wouldn't mind merging them nicely and
#    chronologically.

# status:
#   sorting and merging text - sortof.
#   list of files changed - yes
#   tag support - yes: 'twas hard
#   vendor tag support - yes
#   branch support - yes

# NOTE: a newly created branch with no commits inside will not show up.
#       this is because CVS works that way, and nothing can be done.
#
# NOTE: tagging files in a new branch will really tag the parent. weird CVS.
#
# NOTE: create branch, it says CREATE BRANCH, then add some files onto the
#       trunk, and it says CREATE BRANCH again for *those* files. this is
#       really what happens, since the branch is created for those files
#       only at that point. so this isn't a bug either.
#
# BUGS: infinite nesting in e.g.413.
#
# BUGS: sorting is not polished up yet, so sometimes entries with almost the
#       same timestamp are repeated - e.g. with Initial revision and Import


eval 'exec perl -w -S $0 "$@"'
if 0;

my $opt_files = 1;
my $opt_log = 1;
my $opt_tree = 1;

optloop:
while ($#ARGV >= 0) {
  if ($ARGV[0] eq "--nofiles") { shift; $opt_files = 0; }
  elsif ($ARGV[0] eq "--nolog")   { shift; $opt_log = 0; }
  elsif ($ARGV[0] eq "--notree")  { shift; $opt_tree = 0; }
  elsif (($ARGV[0] eq "--help" || $ARGV[0] =~ /^-[\?h]$/i)) {
    open(F,$0) || die "no help\n";
    while (<F>) { exit if (/^\s*$/); s/^# ?/ /; print if (!/^:/); }
    exit;
  }
  else { last optloop; }
}

if (-t STDIN) {
  open(CVS, "cvs log ".join(' ',@ARGV)." |") || die "can't execute cvs: $!\n";
} else {
  *CVS = STDIN;
}

$dash = "-"x28;
$ddash = "="x77;
$inheader = 1; %symbtag = (); %tagnfiles = ();

sub wraprint {
  my $n = $_[1];
  my $pad = $_[2];
  my $join = $_[3];
  my $len = 0;
  my $res = "";
  foreach (split(/\s+/,$_[0])) {
    if ($len + length($_) + 2 < $n) {
      do { $res .= "$join "; $len += 1+length($join); } if ($res ne "");
    } else {
      $res .= "$join\n"; $len = 0;
    }
    do { $res .= $pad; $len += length($pad); } if ($len == 0);
    $res .= $_; $len += length($_);
  }
  return $res;
}

fileentry:
while (<CVS>) { chomp;

  if (!$inheader && ($_ eq $dash || $_ eq $ddash)) {
    my $k = join(' ', map { s/\s*;$//; "$file:$_" } (split(/\s+/,$branch)));
    %d = ( 'file'	=> $file,
	   'frev'	=> "$file:$rev",
	   'txt'	=> $txt,
	   'rev'	=> $rev,
	   'date'	=> $date,
	   'branch'	=> $k,
	 );
    push @table, { %d };
  }

  if ($_ eq $dash) {
    $inheader = 0;
    $_ = <CVS>; chomp; s/revision\s*//; $rev = $_;
    $_ = <CVS>; chomp; $date = $_;
    $_ = <CVS>; chomp;
    $txt = "";
    $branch = (/^branches:\s*(.*)$/) ? $1 : do { $txt .= "$_\n"; ""; };
  } elsif ($_ eq $ddash) {
    $inheader = 1; undef $file;
    next fileentry;
  } else {
    if ($inheader) {
      $file = $1 if (/^Working file: (.*)$/);
      if (/^\t([^\s]*)\s*:\s*([^\s]*)\s*$/) {
	die if (!defined($file));
	my ($tag,$ver) = ($1,$2);

	# if $ver has an even number of dot-separateds and the
	# second-to-last is zero, then wipe it. this is a branch.
	my @ver = split(/\./,$ver);
	$ver = join('.',(@ver[0..$#ver-2],$ver[$#ver]))
	  if ($#ver >= 1 && ($#ver % 2) && $ver[$#ver-1] eq "0");

	defined($tagnfiles{$tag}) ?
	  do { $tagnfiles{$tag}++ } :
	  do { $tagnfiles{$tag} = 1 };
	my @t = (defined($symbtag{$file}{$ver}) ?
	    @{ $symbtag{$file}{$ver} } : ());
	push @t, $tag;
	$symbtag{$file}{$ver} = [ @t ];
      }
    } else {
      $txt .= "$_\n";
    }
  }
}

foreach (keys(%tagnfiles)) { $tagnfiles1{$_} = $tagnfiles{$_}; } # backup

sub brname {
  my %b = ();
  foreach (split(/\s+/,$_[0])) {
    my ($file,$ver) = split(/:/,$_);
    $ver =~ s/;$//;
    my @ver = split(/\./,$ver);
    pop @ver if ($#ver % 2);
    $ver = join('.',@ver);
    my $x = $symbtag{$file}{$ver};
    $b{@{$x}[0]} = 1 if (defined($x));
  }
  return join(' ',keys(%b));
}

# complicated sort/merge:
# sort on timestamp, largely.
# however, if two entries have the same hours and minutes, then *merge* on
# text and sort on timestamp of the first one anyway.
# XXX ABOVE NOT YET FULLY IMPLEMENTED.
sub cmpval {
  my %a = %{$_[0]}; my $s = $a{date};
  $s =~ s/^([^:]*:[^:]*:[^:]*):.*/$1/; $s.$a{rev}.$a{txt}.$a{frev} };
@table = sort { cmpval($a) cmp cmpval($b) } @table;

# merge consequtive entries with the same text - not all entries, note.
my $m = "garbage";
my @mtable = ();
foreach (@table) {
  my %entry = %{$_};
  if ($m eq $entry{txt}) { # then skip
    $mtable[$#mtable]{frev} .= " " . $entry{frev};
    $mtable[$#mtable]{file} .= " " . $entry{file};
    foreach my $tag (@{ $symbtag{$entry{file}}{$entry{rev}} }) {
      $tagnfiles{$tag}--;
      unshift (@{$mtable[$#mtable]{tags}},$tag) if ($tagnfiles{$tag} <= 0);
    }
  } else {
    $m = $entry{txt};
    $entry{tags} = ();
    foreach my $tag (@{ $symbtag{$entry{file}}{$entry{rev}} }) {
      $tagnfiles{$tag}--;
      unshift (@{$entry{tags}},$tag) if ($tagnfiles{$tag} <= 0);
    }
    push @mtable, { %entry };
  }
}

sub nfiles { " <$tagnfiles1{$_[0]} file".($tagnfiles1{$_[0]}==1?"":"s").">\n" }
sub xprint { print @_ if ($opt_log); }

%child = ();
foreach (@mtable) {
  my %entry = %{$_};
  my $b = brname($entry{frev});
  xprint "BRANCH [$b]\n" if ($b ne "");
  xprint "\n";
  xprint "($entry{date})\n";
  do { xprint wraprint($entry{frev},77,"  | ",",") . "\n  `" . ("-"x40) . "\n" }
    if ($opt_files);
  xprint "\n$entry{txt}\n";
  foreach (@{$entry{tags}}) {
    xprint "*** CREATE TAG [$_]" . nfiles($_);
    push @{$child{$b}}, "t $_";
  }
  foreach (split(/\s+/,brname($entry{branch}))) {
    xprint "*** CREATE BRANCH [$_]" . nfiles($_);
    push @{$child{$b}}, "b $_";
  }
  xprint "" . ("="x78) . "\n";
}

%seen = ();
sub print_branch {
  $seen{$_[0]} = 1;
  my $t = $child{$_[0]};
  my @t = (defined($t)?@{$t}:());
  shift;
  my @were_last = @_;
  my $am_last = 0;
  foreach (@t) {
    $am_last = 1 if ($_ eq $t[$#t]);
    /^(.) (.*)/; my $tb = $1; $_ = $2;
    print(join('',map {($_?" ":"|")."  "} @were_last).($am_last?"`":"|")."- ".($tb eq "b"?"[":"")."$_".($tb eq "b"?"]":"").nfiles($_))
      if ($tb ne "b" || !defined($seen{$_}));
    print_branch($_, (@were_last,$am_last))
      if ($tb eq "b" && !defined($seen{$_}));
  }
}

do { print "HEAD\n"; print_branch("", ()); } if ($opt_tree);
