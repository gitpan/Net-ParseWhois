package Net::ParseWhois::Domain;
require 5.004;

$Net::ParseWhois::Domain::VERSION = 0.5;
@Net::ParseWhois::Domain::ISA = qw(Net::ParseWhois);

use Net::ParseWhois::Domain::Registrar;
use strict;
use Carp;

BEGIN {
  if (eval { require Locale::Country }) {
    Locale::Country->import(qw(code2country country2code));
    }else {
    *code2country = sub { ($_[1] =~ /^[^\W\d_]{2}$/i) && $_[1] };
    *country2code = sub { undef };
  }
}

sub new {
	my $obj = shift;
	my $class = ref($obj) || 'Net::ParseWhois::Domain';
	croak "usage: new $class DOMAIN" if (!@_);
	my $self = { 'domain' 				=> shift,
				 'base_server' 			=> 'whois.nsiregistry.com',
				 'base_server_addr' 	=> undef,
				 'whois_referral' 		=> undef,
				 'nameservers'			=> undef
				 };
	bless($self, $class);
    my $opt = shift;
    if ($opt->{'debug'}) {
        $self->debug( $opt->{'debug'} );
    }
	return $self->chase_referral;
}

# trys to chase_referral in specific registrar class or sets $self->ok = 0
sub chase_referral {
	my $self = shift;
	
	my @zone_parts = split(/\./, $self->{'domain'});
	my $tld = $zone_parts[$#zone_parts];
	$tld =~ tr /a-z/A-Z/; #uppercase key
	warn "$tld = $tld\n" if $self->debug;
	$self->{'base_server_name'} = $self->TLDs->{$tld} if defined $self->TLDs->{$tld};

	if (!$self->{'base_server_name'}) {
		die "unknown TLD - $tld\n";
	}

	my $text = $self->_send_to_sock($self->_connect, "=$self->{'domain'}\x0d\x0a");
	# = make NSI Registry return only one result. enter just register.com there
	# without the equal to see what happens..

	foreach my $t (@{ $text} ) {
        warn "whois line = $t ..\n" if $self->debug;
		if ($t =~ /^No Match for \"/i) {
			$self->{'MATCH'} = 0;
		} elsif ($t =~ /Whois Server: (\S+)/) {
			$self->{'MATCH'} = 1;
			$self->{'whois_referral'} = $1;
			warn "whois_referral = $1\n" if $self->debug;
		} elsif ($t =~ /Name Server: (\S+)/) {
			push(@{ $self->{'nameservers'} }, $1);
			warn "nameserver: $1\n" if $self->debug;
		} 
	}
	
	if ($self->{'whois_referral'}) {
		my $ref = Net::ParseWhois::Domain::Registrar::registrar_data()->{$self->{'whois_referral'}} || "";
		unless ($ref) {
			$ref = Net::ParseWhois::Domain::Registrar::registrar_data()->{'unknown_registrar'};
			$ref->{'UNKNOWN_REGISTRAR'} = 1;
			$ref->{'error'} = "Sorry, I don't know how to parse output from $self->{'whois_referral'}";
			warn "Sorry, I don't know how to parse output from $self->{'whois_referral'}\n" if $self->debug;
		}
		my $class = 'Net::ParseWhois::Domain::Registrar::' . $ref->{'class'};
		$self->_load_module($class);
		my $rc = $class->new( { 
					%{ $ref }, 
					domain => $self->{'domain'}, 
					whois_referral => $self->{'whois_referral'} 
					} );
		return $rc->follow_referral;
	} else {
		# TODO catch if no whois_referral line .. set $self->{error}, something
		# Net::Whois behavior is to just return undef
		return $self;
	}


}

sub ok {
  my $self = shift;
  $self->{MATCH};
}

1;

