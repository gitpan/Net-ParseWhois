#!/usr/bin/perl -w

use strict;
use lib('../blib/lib');

use Net::ParseWhois;

my $dom = $ARGV[0] || die "usage:\n$0 [dom]\n"; 
my $w = Net::ParseWhois::Domain->new($dom, { debug => 0 });
unless (defined $w) { die "Can't connect to Whois server - $w\n";}

unless ($w->ok) {
	die "No match for $dom\n";
}

if ($w->unknown_registrar) {
	die "domain found, registrar unknown. raw data follows\n" . $w->raw_whois_text . "\n";
}

print "Registrar: ", $w->registrar, "\n";
print "Domain: ", $w->domain, "\n";
print "Name: ", $w->name, "\n";
print "Tag: ", $w->tag, "\n";
print "Address:\n", map { "    $_\n" } $w->address;
print "Country: ", $w->country, "\n";
print "Name Servers:\n", map { "    $$_[0] ($$_[1])\n" }
  @{$w->servers};
my ($c, $t);
if ($c = $w->contacts) {
  print "Contacts:\n";
  for $t (sort keys %$c) {
    print "    $t:\n";
    print map { "\t$_\n" } @{$$c{$t}};
  }
}

print "Record created:", $w->record_created ;
print "\nRecord updated:", $w->record_updated,"\n";

