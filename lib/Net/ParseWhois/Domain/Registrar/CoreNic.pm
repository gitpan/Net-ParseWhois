package Net::ParseWhois::Domain::Registrar::CoreNic;

require 5.004;
use strict;

@Net::ParseWhois::Domain::Registrar::CoreNic::ISA = qw(Net::ParseWhois::Domain::Registrar);
$Net::ParseWhois::Domain::Registrar::CoreNic::VERSION = 0.1;

sub rdebug { 0 }
sub regex_no_match { '^No match for' }
sub regex_domain { '^domain:\s*(.*)$' }
sub regex_org { '^o[wr][ng][ea][rn]i?z?a?t?i?o?n?:\s*(.*)$' }
sub regex_tag { '^origin-c:\s*(.*)$' }
sub regex_address { '^address:\s*(.*)$' }
sub regex_city { '^city:\s*(.*)$' }
sub regex_state { '^state:\s*(.*)$' }
sub regex_zip { '^postal-code:\s*(.*)$' }
sub regex_country { '^country:\s*(.*)$' }
sub regex_admin { '^admin-c:\s*(.*)$' }
sub regex_tech { '^tech-c:\s*(.*)$' }
sub regex_zone { '^zone-c:\s*(.*)$' }
sub regex_created { '^created:\s*(.*)$' }
sub regex_updated { '^modified:\s*(.*)$' }
sub regex_expires { '^expires:\s*(.*)$' }
sub regex_nserver { '^nserver:\s*(\S*)\s*(.*)$' }
sub regex_registrar { '^registrar:\s*(.*)$' }
sub my_contacts { [ qw(Administrative Technical Zone) ] }
sub my_data { [ qw(my_contacts regex_no_match regex_domain regex_org regex_tag regex_address regex_city regex_state regex_zip regex_country regex_admin regex_tech regex_zone regex_created regex_updated regex_expires regex_nserver regex_registrar) ] }

sub parse_text {
	my $self = shift;
	my $text = shift; # array ref, one line per element

	$self->dump_text($text) if $self->rdebug;

	$self->parse_start($text);

	return $self;
}

# replace folow_referral so that we can do --format=ripe to get
# easily parsable output and --where=domain:fqdn to match only domains
sub follow_referral {
	my $self = shift;
	$self->{'base_server'} = $self->whois_server;
	my $sock = $self->_connect || die "unable to open connection\n";
	my $text = $self->_send_to_sock( $sock,
		"--format=ripe --where=domain:fqdn $self->{'domain'}\x0d\x0a" );
	$self->{RAW_WHOIS_TEXT} = join("\n", @{ $text } );
	$self->parse_text($text);
}

# This should probably all be in parse_text but it seemed nicer to
# break it out
sub parse_start {
	my $self = shift;
	my $text = shift;

	# the first line should contian regex_no_match or else good data
	my $t = ${ $text }[0];
	if (!defined $t || $t =~ /$self->{'regex_no_match'}/) {
		$self->{'MATCH'} = 0;
		return 0;
	} else {
		$self->{'MATCH'} = 1;
	}

	for (@{$text}) {
		/$self->{'regex_domain'}/	&& do { $self->{'DOMAIN'} = $1; next; };
		/$self->{'regex_org'}/		&& do { $self->{'NAME'} = $1; next; };
		/$self->{'regex_tag'}/		&& do { $self->{'TAG'} = $1; next; };
		/$self->{'regex_address'}/	&& do {
			push @{$self->{'ADDRESS'}}, $1; next; };
		/$self->{'regex_city'}/		&& do {
			push @{$self->{'ADDRESS'}}, $1; next; };
		/$self->{'regex_state'}/	&& do {
			${$self->{'ADDRESS'}}[$#{$self->{'ADDRESS'}}] .= ", $1"; next; };
		/$self->{'regex_zip'}/		&& do {
			${$self->{'ADDRESS'}}[$#{$self->{'ADDRESS'}}] .= " $1"; next; };
		/$self->{'regex_country'}/	&& do { $self->{'COUNTRY'} = $1; next; };
		/$self->{'regex_admin'}/	&& do {
			${$self->{'CONTACTS'}}{uc ${$self->{'my_contacts'}}[0]}
				= [ $self->parse_contacts($1) ];
			next; };
		/$self->{'regex_tech'}/		&& do {
			${$self->{'CONTACTS'}}{uc ${$self->{'my_contacts'}}[1]}
				= [ $self->parse_contacts($1) ];
			next; };
		/$self->{'regex_zone'}/		&& do {
			${$self->{'CONTACTS'}}{uc ${$self->{'my_contacts'}}[2]}
				= [ $self->parse_contacts($1) ];
			next; };
		/$self->{'regex_created'}/	&& do {
			$self->{'RECORD_CREATED'} = $1; next; };
		/$self->{'regex_updated'}/	&& do {
			$self->{'RECORD_UPDATED'} = $1; next; };
		/$self->{'regex_expires'}/	&& do {
			$self->{'RECORD_EXPIRES'} = $1; next; };
		/$self->{'regex_nserver'}/	&& do {
			push @{$self->{'SERVERS'}}, [$1, $2]; next; };
		/$self->{'regex_registrar'}/	&& do {
			$self->{'registrar_tag'} .= " ($1)"; next; };
		#print "\"$_\"\n";
	}
}


# this goes out and gets the contact info
sub parse_contacts {
	my $self = shift;
	my $contactid = shift;
    warn "using cached contact object for contact id $contactid\n" if ($self->{'CONTACT_' . $contactid} && $self->rdebug); 
    return @{ $self->{'CONTACT_' . $contactid} } if ($self->{'CONTACT_' . $contactid});
	$self->{'base_server'} = $self->whois_server;
	my $sock = $self->_connect || die "unable to open connection\n";
	my $text = $self->_send_to_sock( $sock,
		"--where=contact:handle $contactid\x0d\x0a" );
	
	# the first line should contian regex_no_match or else good data
	my $t = ${ $text }[0];
	if (!defined $t || $t =~ /no Match for/) {
		return "";
	}
	my @t = ();
	push @t, shift @{ $text } while ${ $text }[0]; # read until empty line

    $self->{'CONTACT_' . $contactid} = \@t;
	return @t;
}

1;

