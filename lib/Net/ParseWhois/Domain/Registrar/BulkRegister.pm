package Net::ParseWhois::Domain::Registrar::BulkRegister;

require 5.004;
use strict;

@Net::ParseWhois::Domain::Registrar::BulkRegister::ISA = qw(Net::ParseWhois::Domain::Registrar);
$Net::ParseWhois::Domain::Registrar::BulkRegister::VERSION = 0.5;

sub rdebug { 0 }
sub regex_org_start { '^$'}
sub regex_no_match { '^Not found\!' }
sub regex_created { '^Record created on (.*).$' }
sub regex_expires { '^Record expires on (.*).$' }
sub regex_updated { '^Record updated on (.*).$' }
sub regex_domain { '^Domain Name: (.*)$' }
sub regex_nameservers { '^Domain servers in listed order:$' }
sub my_contacts { [ qw(Administrative Technical) ] }
sub my_data { [ qw(my_contacts regex_org_start regex_no_match regex_created regex_expires regex_updated regex_domain regex_nameservers) ] }

sub parse_text {
	my $self = shift;
	my $text = shift; # array ref, one line per element

	$self->dump_text($text) if $self->rdebug;
	$self->parse_start($text);
	$self->parse_org($text);
	$self->parse_domain_name($text);
	$self->parse_contacts($text);
	$self->parse_domain_stats($text);
	$self->parse_nameservers($text);

	return $self;
}

sub parse_start {
	my $self = shift;
	my $text = shift; 

    my $t = shift @{ $text };
	if (!defined $t || $t =~ /$self->{'regex_no_match'}/) {
		$self->{'MATCH'} = 0;
	} else {
		$self->{'MATCH'} = 1;
		if ($t =~ /^(.*)$/) {
			$self->{'NAME'} = $1;
			if ($self->{'NAME'} =~ /^(.*)\s+\((\S+)\)$/) {
				$self->{'NAME'} = $1;
				$self->{'TAG'} = $2;
			}
		} else {
			die "Registrant Name not found in returned information\n";
		}
	}
}


1;
