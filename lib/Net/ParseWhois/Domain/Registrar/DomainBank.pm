package Net::ParseWhois::Domain::Registrar::DomainBank;

require 5.004;
use strict;

# TODO:
# this one needs work on parse_contacts .. try domainbank.net and domainbank.com.
# bleh.

@Net::ParseWhois::Domain::Registrar::DomainBank::ISA = qw(Net::ParseWhois::Domain::Registrar);
$Net::ParseWhois::Domain::Registrar::DomainBank::VERSION = 0.1;

sub rdebug { 0 }
sub regex_org_start { '^Registrant:'}
sub regex_no_match { '^No Match for' }
sub regex_created { '^Record created on (.*)$' }
sub regex_expires { '^Record expires on (.*)$' }
#sub regex_updated { } # why doesn't domainbank show the last update time .. ?
sub regex_domain { '^Domain: (.*)$' }
sub regex_nameservers { '^Domain servers in listed order:$' }
sub my_contacts { [ qw(Administrative Technical Zone) ] }
sub my_contacts_extra_line { 1 }
sub my_data { [ qw(my_contacts_extra_line my_contacts regex_org_start regex_no_match regex_created regex_expires regex_domain regex_nameservers) ] }

sub parse_text {
	my $self = shift;
	my $text = shift; # array ref, one line per element

	$self->dump_text($text) if $self->rdebug;

	$self->parse_start($text);
	$self->parse_org($text);
	$self->parse_domain_name($text);
	$self->parse_contacts($text);

	$self->dump_text($text) if $self->rdebug;

	$self->parse_domain_stats($text);
	$self->parse_nameservers($text);

	return $self;
}


sub parse_domain_stats { 

# required because they don't have UPDATED info .. changing base class would
# be complicated, and I think ICANN requires the updated: string in whois output.
# --aai

	my ($self, $text) = @_;
	while (@{ $text}) {
		last if ($self->{RECORD_CREATED} && $self->{RECORD_EXPIRES});
		my $t = shift(@{ $text });
		next if $t=~ /^$/;
		if ($t =~ /$self->{'regex_created'}/) {
			$self->{RECORD_CREATED} = $1;
		} elsif ($t =~ /$self->{'regex_expires'}/) {
			$self->{RECORD_EXPIRES} = $1;
		}
	}
}


1;
