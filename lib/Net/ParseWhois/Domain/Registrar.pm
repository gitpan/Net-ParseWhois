package Net::ParseWhois::Domain::Registrar;
require 5.004;
use strict;

$Net::ParseWhois::Domain::Registrar::VERSION = 0.01;
@Net::ParseWhois::Domain::Registrar::ISA = qw(Net::ParseWhois::Domain);

sub my_data {} # used by new to import vals into $self->{} in specific registrar classes

sub registrar_data {
	{
	'whois.dotster.com'	=> {
			'registrar_tag'	=>	'DOTSTER, INC.',
			'referral_tag' 	=> 	'http://www.dotster.com/help/whois',
			'class'			=>	'Dotster' },
	'whois.register.com' => {
			'registrar_tag' => 	'REGISTER.COM, INC.',
			'referral_tag'	=>	'www.register.com',
			'class'			=>	'Register' },
	'whois.networksolutions.com' => {
			'registrar_tag'	=>	'NETWORK SOLUTIONS, INC.',
			'referral_tag'	=>	'www.networksolutions.com',
			'class'			=>	'Netsol' },
	'whois.opensrs.net' => {
			'registrar_tag' =>	'TUCOWS.COM, INC.',
			'referral_tag'	=>	'www.opensrs.org',
			'class'			=>	'OpenSRS' },
	'whois.domaindiscover.com' => {
			'registrar_tag' =>	'TIERRANET, INC.',
			'referral_tag'	=>	'www.domaindiscover.com',
			'class'			=>	'DomainDiscover' },
	'whois.bulkregister.com' => {
			'registrar_tag' =>	'BULKREGISTER.COM, INC.',
			'referral_tag'	=>	'www.bulkregister.com',
			'class'			=>	'BulkRegister' },
	'rs.domainbank.net'		=> {
			'registrar_tag'	=>	'DOMAIN BANK, INC.',
			'referral_tag'	=>	'www.domainbank.net',
			'class'			=>	'DomainBank' },
	'whois.registrars.com'		=> {
			'registrar_tag'	=>	'INTERNET DOMAIN REGISTRARS',
			'referral_tag'	=>	'www.registrars.com',
			'class'			=>	'Registrars' },
	'unknown_registrar'		=> {
			'registrar_tag'	=>	'Unknown',
			'referral_tag'	=>	'n/a',
			'class'			=>	'Unknown' }

	}		
	# see perldoc Net::ParseWhois section 'REGISTRARS'
}

sub parse_start {
	my $self = shift;
	my $text = shift; 

    my $t = shift @{ $text };
    until (!defined $t || $t =~ /$self->{'regex_org_start'}/ || $t =~ /$self->{'regex_no_match'}/) {
		$t = shift @{ $text };
    }

    $t =~ s/^\s//;		#trim whitespace
	$t = shift @{ $text } if ($t eq '');

    if ($t =~ /$self->{'regex_org_start'}/) {
		$t = shift @{ $text };
		$self->{'MATCH'} = 1;
	} elsif ($t =~ /$self->{'regex_no_match'}/) { # since we have a referral, this should never get caught. --aai
		$self->{'MATCH'} = 0;
    }
    if ($self->{'MATCH'} ) { 
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

sub parse_org { 
	my $self = shift;
	my $text = shift;

	my (@t, $c, $t);
    @t = ();
    push @t, shift @{ $text } while	${ $text }[0]; # read in text until next empty line

	if ($self->{'my_country_position'}) {
    	$t = $t[$#t - $self->{'my_country_position'}];
	} else {
    	$t = $t[$#t];
	}
    if (!defined $t) {
		# do nothing
	} elsif ($t =~ /^(?:usa|u\.\s*s\.\s*a\.)$/i) {
		pop @t;
		$t = 'US';
	} elsif ($self->code2country($t)) {
		pop @t;
		$t = uc $t;
	} elsif ($c = $self->country2code($t)) {
		pop @t;
		$t = uc $c;
	} elsif ($t =~ /,\s*([^,]+?)(?:\s+\d{5}(?:-\d{4})?)?$/) {
		# TODO - regex is too rigid. lots of times this shouldn't be matched
		# because a tel/fax line exists after address3/city,state zip ..
		$t = $self->US_State->{uc $1} ? 'US' : undef;
	} else {
		undef $t;
	}
    $self->{ADDRESS} = [@t];
    $self->{COUNTRY} = $t;
}

sub parse_contacts {
	my ($self, $text) = @_;
	while (@{ $text }) {
		my $done = 1;
		foreach my $ck (@{ $self->{'my_contacts'} }) {
			unless ($self->{CONTACTS}->{uc($ck)}) {
				$done = 0;
			}
		}
		last if $done;
		my $t = shift(@{ $text });
		next if $t=~ /^$/;
		if ($t =~ /contact.*:$/i) {
			my @ctypes = ($t =~ /\b(\S+) contact/ig);
			my @c;
			if ($self->{'my_contacts_extra_line'}) {
				my $blah = shift(@{ $text });
			}
			while ( ${ $text }[0] ) {
				last if ${ $text }[0] =~ /contact.*:$/i;
				push @c, shift @{ $text };
			}
			@{ $self->{CONTACTS} } {map {uc} @ctypes} = (\@c) x @ctypes;
		}
	}
}

sub parse_nameservers {
	my ($self, $text) = @_;
	while (@{ $text }) {
		last if ($self->{SERVERS});
		my $t = shift(@{ $text });
		next if $t =~ /^$/;
		if ($t =~ /$self->{'regex_nameservers'}/) {
			my @s;
			shift @{ $text } unless ${ $text }[0];
			while ($t = shift @{ $text }) {
				if ($self->{'my_nameservers_noips'}) {
					my @temp = [ $t, $self->na ];
					push @s, @temp;
				} else {
					push @s, [split /\s+/,  $t];
				}
			}
			$self->{SERVERS} = \@s;
		}
	}
}

sub parse_domain_stats { 
	my ($self, $text) = @_;
	while (@{ $text}) {
		last if ($self->{RECORD_CREATED} && $self->{RECORD_UPDATED} && $self->{RECORD_EXPIRES});
		my $t = shift(@{ $text });
		next if $t=~ /^$/;
		if ($t =~ /$self->{'regex_created'}/) {
			$self->{RECORD_CREATED} = $1;
		} elsif ($t =~ /$self->{'regex_updated'}/) {
			$self->{RECORD_UPDATED} = $1;
		} elsif ($t =~ /$self->{'regex_expires'}/) {
			$self->{RECORD_EXPIRES} = $1;
		}
	}
}

sub parse_domain_name { 
	my $self = shift;
	my $text = shift;

	while (@{ $text}) {
		last if ($self->{DOMAIN});
		my $t = shift(@{ $text });
		next if $t=~ /^$/;
		if ($t =~ /$self->{'regex_domain'}/) {
			$self->{DOMAIN} = $1;
		}
	}
}

sub new {
	my $class = shift;
	my $ref = shift;
	my %hash = %{ $ref } if ($ref);
	my $obj = bless ( \%hash, $class );
	
	if (defined $obj->my_data) {
		foreach my $field (@{ $obj->my_data }) {
			$obj->{$field} = $obj->$field();
		}
	}
	return $obj;
}
		
sub na {
	return "n/a";
}

sub follow_referral {
	my $self = shift;
	$self->{'base_server'} = $self->whois_server;
	my $sock = $self->_connect || die "unable to open connection\n";
	my $text = $self->_send_to_sock( $sock );
	$self->{RAW_WHOIS_TEXT} = join("\n", @{ $text } ); 
	if ($self->unknown_registrar) { # don't parse, just return $self with raw data
		$self->{MATCH} = 1;
		return $self;
	} else {
		$self->parse_text($text);
	}
}

sub whois_server {
	my $self = shift;
	return $self->{'whois_referral'};
}

sub dump_text {
	my $self = shift;
	my $text = shift;
	warn "raw registry data:\n----------------------------------\n";
	foreach (@{ $text }) {
		warn "\"$_\"\n";
	}
	warn "----------------------------------\nend registry data.\n";
}
	
sub parse_text {
	my $self = shift;
	my $text = shift;

	warn "$self->parse_text NOT defined. Dumping data, and then dieing.\n" if $self->debug;
	foreach my $line (@{ $text }) {
		print "$line\n";
	}
	#TODO get rid of die ..
	die "$self->parse_text not defined.\n";
	return $self;
}


# TODO
# all of the below is silly. Via these accessor methods we should also be
# setting the values, rather than using UPPERCASE hash keys in $self. 
# or these should be named get_domain, get_name, etc.
# right .. ? --aai 12/05/00

sub	domain {
	my $self = shift;
	$self->{DOMAIN} || $self->na;
}

sub	name {
	my $self = shift;
	$self->{NAME} || $self->na;
}

sub tag {
	my $self = shift;
	$self->{TAG} || $self->na;
}

sub	address {
	my $self = shift;
	my $addr = $self->{ADDRESS} || [ $self->na ];
	wantarray ? @ $addr : join "\n", @$addr;
}

sub country {
	my $self = shift;
	$self->{COUNTRY} || $self->na;
}

sub contacts {
	my $self = shift;
	$self->{CONTACTS} || { $self->na };
}

sub registrar {
	my $self = shift;
	return $self->{'registrar_tag'} || $self->na;
}

sub servers {
	my $self = shift;
	if (!$self->{SERVERS}) { # TODO: yuck ..
		my (@tmp, @ret);
		push(@tmp, $self->na);
		push(@tmp, $self->na);
		my $ref = \@tmp;
		push(@ret, $ref);
		return \@ret;
	}

	return $self->{SERVERS};
}

sub record_created {
	my $self = shift;
	$self->{RECORD_CREATED} || $self->na;
}

sub	record_updated {
  my $self = shift;
  $self->{RECORD_UPDATED} || $self->na;
}

sub	record_expires {
  my $self = shift;
  $self->{RECORD_EXPIRES} || $self->na;
}

sub raw_whois_text { 
	my $self = shift;
	$self->{RAW_WHOIS_TEXT} || $self->na;
}

sub unknown_registrar {
	my $self = shift;
	$self->{UNKNOWN_REGISTRAR} || '0';
}



1;
