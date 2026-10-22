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
# The optional texts (sameop, broken1, broken2) come from the input's "files".
sub read_file { $Stub::Storage::DATA->{files}{$_[0]} }
package Echolot::Chain;
# find_broken_chains hands its intensive care list here (E:Chain.pm:209-218).
our %IC;
sub set_intensive_care { my ($t, $ic) = @_; $IC{$t} = { map { ($_->{addr1}.' '.$_->{addr2}) => $_->{reason} } @$ic } }
package Stub::Storage;
our $DATA;
sub new { bless {}, shift }
sub get_addresses { map { { address => $_, showit => $DATA->{rems}{$_}{showit} // 1 } } sort keys %{$DATA->{rems}} }
sub has_type { my ($s,$a,$t)=@_; return ($t eq 'mix' && scalar keys %{$DATA->{rems}{$a}{keys}}) ? 1 : 0 }
sub get_keys { my ($s,$a,$t)=@_; sort keys %{$DATA->{rems}{$a}{keys}} }
sub get_pings { my ($s,$a,$t,$k,$d)=@_; my $p=$DATA->{rems}{$a}{keys}{$k}; return $d eq 'out' ? @{$p->{out}} : map { [@$_] } @{$p->{done}} }
sub get_nick { $DATA->{rems}{$_[1]}{nick} }
sub get_capabilities { $DATA->{rems}{$_[1]}{caps} }
# The input's "chainpings" are [sent, addr1, addr2, latency or null], all of
# type mix.  Echolot's "out" holds every chain ping sent, "done" those back
# (E:Storage/File.pm:765-835).
sub get_chainpings {
	my ($s, $t) = @_;
	my (@out, @done);
	for my $p ($t eq 'mix' ? @{$DATA->{chainpings} // []} : ()) {
		my %p = (sent => $p->[0], addr1 => $p->[1], type1 => 'mix', key1 => 'k1',
			addr2 => $p->[2], type2 => 'mix', key2 => 'k2');
		push @out, {%p};
		push @done, {%p, lat => $p->[3]} if defined $p->[3];
	}
	return { out => \@out, done => \@done };
}
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
my $chains = exists $Stub::Storage::DATA->{chainpings};
$Echolot::Config::C = { stats_days => 12, seconds_per_day => 86400,
	pings_weight => [ qw{0.5 1.0 1.0 1.0 1.0 0.9 0.8 0.5 0.3 0.2 0.2 0.1} ],
	stats_sort_by_latency => 0, buildstats => 300,
	do_chainpings => 0, show_chainpings => 0, combined_list => 0, separate_rlists => 0,
	resultdir => "$outdir/pub", private_resultdir => "$outdir/priv",
	indexfilebasename => 'echolot', echolot_css => '/dev/null',
	broken1 => 'broken1', broken2 => 'broken2', sameop => 'sameop' };
# An input with "chainpings" (even empty) turns chain pings on, with
# Echolot's chain settings (E:Config.pm:123-131).
if ($chains) {
	%$Echolot::Config::C = (%$Echolot::Config::C, do_chainpings => 1, show_chainpings => 1,
		chainping_period => 10*24*60*60, chainping_fudge => 0.3, chainping_grace => 1.5,
		chainping_update => 4*60*60, chainping_minsample => 3, chainping_allbad_factor => 0.5);
}
# The input's "config" overrides stats_days, pings_weight and stats_sort_by_latency.
for my $k (qw{stats_days pings_weight stats_sort_by_latency}) {
	$Echolot::Config::C->{$k} = $Stub::Storage::DATA->{config}{$k} if exists $Stub::Storage::DATA->{config}{$k};
}
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
# Chain cases: the intensive care of the type-II evaluation ("addr1 addr2"
# => reason; broken chains are those with "bad: done/out").
if ($chains) {
	open($j, '>', "$outdir/ic.json") or die;
	print $j JSON::PP->new->canonical->pretty->encode($Echolot::Chain::IC{mix} // {});
	close $j;
}
# "compress": [[num, [chain, ...]], ...] runs compress_broken_chain alone.
if (exists $Stub::Storage::DATA->{compress}) {
	my @res = map { [ Echolot::Stats::compress_broken_chain($_->[0], @{$_->[1]}) ] } @{$Stub::Storage::DATA->{compress}};
	open($j, '>', "$outdir/compress.json") or die;
	print $j JSON::PP->new->canonical->pretty->encode(\@res);
	close $j;
}
