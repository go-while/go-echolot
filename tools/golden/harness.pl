#!/usr/bin/perl
# Golden-number harness: runs Echolot's real Stats.pm (build_stats, calculate)
# on synthetic ping data read as JSON, with time() and gmtime() pinned.
# usage: perl harness.pl <path/to/Echolot/Stats.pm> <input.json> <outdir>
use strict;
use warnings;
use JSON::PP;
our $NOW;
BEGIN {
	*CORE::GLOBAL::time   = sub () { return $NOW };
	*CORE::GLOBAL::gmtime = sub (;$) { return CORE::gmtime(@_ ? $_[0] : $NOW) };
	$INC{'Echolot/Log.pm'} = 1;
}
package Echolot::Log;
sub debug {} sub info {} sub notice {} sub warn { print STDERR "warn: @_\n" } sub cluck {} sub confess { die @_ }
package Echolot::Tools;
sub make_dayname { (qw{Sun Mon Tue Wed Thu Fri Sat})[$_[0]] }
sub make_monthname { (qw{Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec})[$_[0]] }
sub write_meta_information { 1 }
sub write_HTML_file { 1 }
sub read_file { undef }
package Stub::Storage;
our $DATA;
sub new { bless {}, shift }
sub get_addresses { map { { address => $_, showit => $DATA->{rems}{$_}{showit} // 1 } } sort keys %{$DATA->{rems}} }
sub has_type { my ($s,$a,$t)=@_; return ($t eq 'mix' && scalar keys %{$DATA->{rems}{$a}{keys}}) ? 1 : 0 }
sub get_keys { my ($s,$a,$t)=@_; sort keys %{$DATA->{rems}{$a}{keys}} }
sub get_pings { my ($s,$a,$t,$k,$d)=@_; my $p=$DATA->{rems}{$a}{keys}{$k}; return $d eq 'out' ? @{$p->{out}} : map { [@$_] } @{$p->{done}} }
sub get_nick { $DATA->{rems}{$_[1]}{nick} }
sub get_capabilities { $DATA->{rems}{$_[1]}{caps} }
package Echolot::Globals;
our $G;
sub get { $G }
package Echolot::Config;
our $C;
sub get { $C }
package main;
my ($stats_pm, $in, $outdir) = @ARGV;
open(my $fh, '<', $in) or die "$in: $!"; my $json = do { local $/; <$fh> }; close $fh;
$Stub::Storage::DATA = decode_json($json);
$NOW = $Stub::Storage::DATA->{now};
mkdir "$outdir/pub"; mkdir "$outdir/priv";
$Echolot::Config::C = { stats_days => 12, seconds_per_day => 86400,
	pings_weight => [ qw{0.5 1.0 1.0 1.0 1.0 0.9 0.8 0.5 0.3 0.2 0.2 0.1} ],
	stats_sort_by_latency => 0, buildstats => 300,
	do_chainpings => 0, show_chainpings => 0, combined_list => 0, separate_rlists => 0,
	resultdir => "$outdir/pub", private_resultdir => "$outdir/priv",
	indexfilebasename => 'echolot', echolot_css => '/dev/null',
	broken1 => 'x', broken2 => 'x', sameop => 'x' };
$Echolot::Globals::G = { storage => Stub::Storage->new };
require $stats_pm;
Echolot::Stats::build_stats();
my %out;
for my $a (sort keys %{$Stub::Storage::DATA->{rems}}) {
	$out{$a} = Echolot::Stats::calculate($a, ['mix']);
}
open(my $j, '>', "$outdir/calc.json") or die;
print $j JSON::PP->new->canonical->pretty->encode(\%out);
close $j;
