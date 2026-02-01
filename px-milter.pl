#!/usr/bin/perl
#-------------------------------------------------------------------------------
my $LastUpdate = '2026.0x.xx';
################################################################################
# PX SPAM milter
################################################################################
# use https://metacpan.org/pod/Sendmail::PMilter
#
BEGIN {
	my $path = $0;
	$path =~ s|/[^/]*||;
	if ($path) { chdir($path); }
	unshift(@INC, './');
}
use strict;
use Fcntl;
use threads;
use Sendmail::PMilter qw(:all);
################################################################################
my $DEBUG = 0;
my $PRINT = 1;
my $PORT  = 10025;
my $MODE;

my $USER_FILTER         = $0 =~ s|^.*/([\w\-\.]+)\.\w+$|$1.user-filter.pm|r;
my $USER_FILTER_PACKAGE = 'px_filter';

my $MILTER_NAME    = 'PX-Milter';
my $DETECT_HEADER  = 'X-Spam-Detect';
#-------------------------------------------------------------------------------
# command line options
#-------------------------------------------------------------------------------
my $TEST_FILE;
{
	my @ary;
	my $HELP;
	my $err  = '';
	while(@ARGV) {
		my $x = shift(@ARGV);
		if ($x eq '-d') { $PRINT = $DEBUG = 1; next; }
		if ($x eq '-s') { $PRINT = 0; next; }
		if ($x eq '-h') { $HELP  = 1; next; }

		if ($x eq '-a')  { $MODE = ''; next; }
		if ($x eq '-r')  { $MODE = SMFIS_REJECT;  next; }
		if ($x eq '-di') { $MODE = SMFIS_DISCARD; next; }

		if ($x eq '-p') {
			$PORT = int(shift(@ARGV));
			next;
		}
		if ($x eq '-t') {
			$TEST_FILE = shift(@ARGV);
			next;
		}
		push(@ary, $x);
	}

	if ($HELP) {
		print STDERR <<HELP;	## safe
Usage: $0 [options]

Available options are:
  -p port	bind port number (default: 10025)
  -t file.eml	milter test mode
  -s		silent mode
  -d		debug mode
  -h		view this help

[Run modes]
  -a		Add "$DETECT_HEADER: yes (reason)" to header (default)
  -r		REJECT  mode
  -di		DISCARD mode
HELP
		exit;
	}

	if (@ary) {
		$err .= "Unknown options: " . join(' ',@ary) . "\n";
	}
	if ($err) {
		print STDERR $err;	## safe
		exit(1);
	}
}

#-------------------------------------------------------------------------------
# Init
#-------------------------------------------------------------------------------
&log("PX SPAM Filter Server -- $LastUpdate");

if (!-e $USER_FILTER) {
	&log("Copy default user filter from $USER_FILTER.sample");
	system('cp', "$USER_FILTER.sample", $USER_FILTER);
}
&load_user_filter();

#-------------------------------------------------------------------------------
# Regist callback
#-------------------------------------------------------------------------------
# callback types: close connect helo abort envfrom envrcpt header eoh eom
#
my %cb;
my $c_name;
my $c_ip;
my $c_host;
my $env_from;
my $rcpt_to;
my $msg_id;
my %header;

my $parser = new MailParser;

$cb{helo} = sub {
	my $ctx = shift;
	#{
        #	daemon_addr => '192.168.0.10',
        #	daemon_name => 'my.example.jp',
        #	v           => 'Postfix 3.10.5',
        #	j           => 'sender_name.example.jp',
        #	_           => 'look_up_host_name [client ip]',
        #};
	eval {
		my $c = $ctx->{symbols}->{C};
		$c_name = $c->{j};
		if ($c->{_} =~ /^([^\s]*)\s\[(.*)\]/) {
			$c_ip   = $2;
			$c_host = $1;	# lookup name
		}
	};
	$DEBUG && print "client name:   $c_name\n";
	$DEBUG && print "client adress: $c_ip\n";
	$DEBUG && print "client host:   $c_host\n";

	return SMFIS_CONTINUE;
};
$cb{envfrom} = sub {
	my $ctx   = shift;
	$env_from = shift =~ s/^<(.*)>$/$1/r;;
	$DEBUG && print "MAIL FROM: $env_from\n";
	return SMFIS_CONTINUE;
};
$cb{envrcpt} = sub {
	my $ctx  = shift;
	$rcpt_to = shift   =~ s/^<(.*)>$/$1/r;
	$DEBUG && print "RCPT TO:   $rcpt_to\n";
	return SMFIS_CONTINUE;
};
$cb{header} = sub {
	my $ctx = shift;
	my $key = shift =~ tr/A-Z/a-z/r;
	my $val = $parser->decode_header_line(shift, 'utf8');

	if ($key eq 'message-id') {	# = <0123456789@domain.example.com>
		$val =~ s/[^\w\-\.\@]//g;
		$msg_id = $val;
		$DEBUG && print "$key: $msg_id\n";
	}
	if (!exists($header{$key})) {
		$header{$key} = $val;
	}
	return SMFIS_CONTINUE;
};

#-------------------------------------------------------------------------------
# Judgment
#-------------------------------------------------------------------------------
$cb{eom} = sub {
	my $ctx = shift;
	my $to_name   = $header{to}   =~ s/\s*<.*//rs;	# remove <adr@dom>
	my $from_name = $header{from} =~ s/\s*<.*//rs;	#
	$to_name   =~ s/^"([^"]*)"$/$1/;		# dequote
	$from_name =~ s/^"([^"]*)"$/$1/;		#
	$DEBUG && print "To name:   $to_name\n";
	$DEBUG && print "From name: $from_name\n";

	my $filter = &load_filter_function();
	if (!$filter) {
		&log("<$msg_id> Accept (filter load failed)");
		return SMFIS_CONTINUE;	# if error continue
	}

	my ($r, $reason) = &$filter({
		c_name	=> $c_name,
		c_ip	=> $c_ip,
		c_host	=> $c_host,
		env_from=> $env_from,
		rcpt_to	=> $rcpt_to,
		msg_id  => $msg_id,
		to_name => $to_name,
		from_name=>$from_name,
		header	=> \%header
	});

	if (!$r) {
		return SMFIS_CONTINUE;	# Accept
	}

	#------------------------------------------
	# detect SPAM
	#------------------------------------------
	if ($reason eq '') { $reason = 'no reason'; }

	&log("<$msg_id> is SPAM ($reason)");
	if ($MODE ne '') { return $MODE; }

	if (ref($ctx) eq 'Sendmail::PMilter::Context') {
		$ctx->addheader($DETECT_HEADER, "yes ($reason)");
	}
	return SMFIS_CONTINUE;
};

#-------------------------------------------------------------------------------
# Start
#-------------------------------------------------------------------------------
if ($TEST_FILE eq '') {
	my $milter = new Sendmail::PMilter;

	&log("bind localhost:$PORT");
	$milter->setconn("inet:$PORT");

	$milter->register($MILTER_NAME, \%cb, SMFI_CURR_ACTS);

	$milter->set_dispatcher(\&my_dispatcher);

	$milter->main();
}

#-------------------------------------------------------------------------------
# Test mode
#-------------------------------------------------------------------------------
else {
	&log("Test mode: file=$TEST_FILE");

	my $lines = &fread_lines($TEST_FILE);

	my @header;
	while(@$lines) {
		my $x = shift(@$lines);
		if ($x =~ /^\r?\n/) { last; }

		while(@$lines && $lines->[0] =~ /^[\t ]+/) {
			$x .= shift(@$lines);
		}
		push(@header, $x);
	}
	my @data = @$lines;
	undef @$lines;

	my %helo_c = (
		daemon_addr => '192.168.0.10',
		daemon_name => 'example.jp',
		v           => 'Postfix 3.10.5'
	);
	my %ctx = ( symbols => { C => \%helo_c } );

	my $env_from;
	my $rcpt_to;
	foreach(@header) {
		if ($_ !~ /Received: /) { next; }
		if ($_ =~ /from +([^\s]+) +\(([^\)]*)\)/) {
			$helo_c{j} = $1;
			$helo_c{_} = $2;
		}
		if ($_ =~ /for <([^>]*)>/) {
			$rcpt_to = $1;
		}
		if ($_ =~ /\(envelope-from ([^\)]*)\)>/) {
			$env_from = $1;
		}
		last;
	}
	if ($env_from eq '') {
		foreach(@header) {
			if ($_ !~ /From: /) { next; }
			if ($_ =~ /<([^>]*)>/ || $_ =~ /([\w\-\.]+\@[\w\-\.]+)/) {
				$env_from = $1;
			}
			last;
		}
	}

	#-----------------------------------------------------------------------
	# callback
	#-----------------------------------------------------------------------
	sub callback {
		my $type = shift;
		my $func = $cb{$type};
		if (!$func) { return; }

		my $r = &$func(\%ctx, @_);
		if ($r == SMFIS_CONTINUE) { return; }

		if ($r == SMFIS_REJECT)   { print "REJECT\n";   }
		if ($r == SMFIS_DISCARD)  { print "DISCARD\n";  }
		if ($r == SMFIS_ACCEPT)   { print "ACCEPT\n";   }
		if ($r == SMFIS_TEMPFAIL) { print "TEMPFAIL\n"; }
		if ($r == SMFIS_MSG_LOOP) { print "MSG_LOOP\n"; }
		if ($r == SMFIS_ALL_OPTS) { print "ALL_OPTS\n"; }
		exit($r);
	}

	&callback('connect');
	&callback('helo');

	if ($env_from ne '') { &callback('envfrom', $env_from); }
	if ($rcpt_to  ne '') { &callback('envrcpt', $rcpt_to);  }

	&callback('data');

	foreach(@header) {
		$_ =~ s/\r?\n$//m;
		&callback('header', split(/:\s*/, $_, 2));
	}
	&callback('eoh');
	&callback('eom');

	print "ACCEPT\n";
}
exit(0);


################################################################################
# dispacher and Milter function
################################################################################
sub get_ithreads {
	return $#{[ threads->list() ]}+1;
}

sub my_dispatcher {		# "$this" is obj of Sendmail::PMilter
	my $this    = shift;
	my $srv     = shift;
	my $handler = shift;
	my $max_ths = $this->get_max_interpreters();

	my $siginfo = exists($SIG{INFO}) ? 'INFO' : 'USR1';
	$SIG{$siginfo} = sub {
		warn "Number of active threads: " . &get_ithreads() . ($max_ths ? "max=$max_ths" : '') . "\n";
	};
	$SIG{PIPE}  = 'IGNORE';

	my $thread_main = sub {
		my $sock = shift;

		eval {
			&$handler($sock);
			$sock->close();
		};
		if ($@) {
			warn $@;
		}
	};
	while (1) {
		my $sock = $srv->accept();
		next if $!{EINTR};

		my $ths = &get_ithreads();
		if ($max_ths && $max_ths <= $ths) {
			&log("maximum threads running: $ths / max=$max_ths");
			close($sock);
			next;
		}

		&load_user_filter();

		my $th = threads->create($thread_main, $sock);
		if (!$th) {
			&log("thread creation failed: $!\n");
			next;
		}
		$th->detach;
	}
}

################################################################################
# load user filter
################################################################################
my $user_filter_size;
my $user_filter_timestamp;

sub load_user_filter {
	if (!-r $USER_FILTER) {
		&log("Can't read user filter: $USER_FILTER");
		unload_filter();
		return;
	}
	my @st   = stat($USER_FILTER);
	my $size = $st[7];
	my $mod  = $st[9];		# last modified

	if ($user_filter_size != $size || $user_filter_timestamp != $mod) {
		# module reload
		unload_filter();
		eval { require $USER_FILTER; };
		if ($@) {
			&log("User filter load error: $@");
			unload_filter();
			return;
		}
		my $re = $user_filter_timestamp ? "re" : '';
		$user_filter_size      = $size;
		$user_filter_timestamp = $mod;
		&log("User filter ${re}load: last modified=" . &get_timestamp($mod) . " / size=$size");
	}
}

sub load_filter_function {
	no strict 'refs';
	return *{$USER_FILTER_PACKAGE . '::main'}{CODE};
}

#-------------------------------------------------------------------------------
# unload
#-------------------------------------------------------------------------------
sub unload_filter {
	no strict 'refs';

	delete $INC{$USER_FILTER};

	# delete from Namespace
	my $names = \%{ $USER_FILTER_PACKAGE . '::' };
	foreach(keys(%$names)) {
		substr($_,-2) eq '::' && next;
		if (ref($names->{$_})) {
			delete $names->{$_};
		} else {
			undef  $names->{$_};	# for scalar, do not "delete" it!
		}
	}

	undef $user_filter_size;
	undef $user_filter_timestamp;
}

################################################################################
# subroutine
################################################################################
#-------------------------------------------------------------------------------
# output log
#-------------------------------------------------------------------------------
sub log {
	if (!$PRINT) { return; }
	my $msg = join('',  @_);
	my $ts  = &get_timestamp();
	chomp($msg);

	local($|) = 1;
	print "$ts $msg\n";
}

sub get_timestamp {
	my $tm = shift || time;
	my ($s,$m,$h,$d,$mon,$y) = localtime($tm);
	return sprintf("%04d-%02d-%02d %02d:%02d:%02d", $y+1900, $mon+1, $d, $h, $m, $s);
}

#-------------------------------------------------------------------------------
# file read
#-------------------------------------------------------------------------------
sub fread_lines {
	my $file = shift;
	sysopen(my $fh, $file, O_RDONLY) || die("File can't read \"$file\"");
	my @lines = <$fh>;
	close($fh);

	return \@lines;
}

################################################################################
# mail parser routine
################################################################################
package MailParser;
use Encode;
use MIME::Base64;
#-------------------------------------------------------------------------------
sub new {
	my $class= shift;
	return bless({}, $class);
}
#-------------------------------------------------------------------------------
# decode for one line
#-------------------------------------------------------------------------------
sub decode_header_line {
	my $self = shift;
	my $line = shift;
	my $code = shift;
	my $ROBJ = $self->{ROBJ};

	if ($line !~ /=\?.*\?=/) { return $line; }
	$line =~ s/\x00//g;

	# MIME
	my @buf;
	$line =~ s/=\?([\w\-]*)\?[Bb]\?([A-Za-z0-9\+\/=]*)\?=/
		my $mime_code = $1;
		my $str = decode_base64($2);
		Encode::from_to($str, $mime_code, $code);
		push(@buf, $str);
		"\x00$#buf\x00";
	/eg;

	# Quoted-Printable
	$line =~ s!=\?([\w\-]*)\?[Qq]\?((?:=[0-9A-Fa-f][0-9A-Fa-f]|[^=]+)*)\?=!
		my $mime_code = $1;
		my $str = $2;
		$str =~ s/=([0-9A-Fa-f][0-9A-Fa-f])/chr(hex($1))/eg;
		Encode::from_to($str, $mime_code, $code);
		push(@buf, $str);
		"\x00$#buf\x00";
	!eg;

	$line =~ s/\x00\s+\x00/\x00\x00/g;	# RFC 2047
	$line =~ s/\x00(\d+)\x00/$buf[$1]/g;	# recovery buffer
	return $line;
}

sub decode_rfc3676 {		# RFC2231
	my $self = shift;
	my $text = shift;
	my $type = shift;

	if ($type !~ m|text/plain|i || $type !~ /format=flowed/i) {
		return $text;
	}
	$text =~ s/(^|\n) /$1/g;
	if ($type =~ /delsp=yes/i) {
		$text =~ s/ \r?\n//g;
	} else {
		$text =~ s/ \r?\n/ /g;
	}
	return $text;
}

sub decode_quoted_printable {	# Content-Transfer-Encoding: quoted-printable
	my $self = shift;
	my $text = shift;
	$text =~ s/=([0-9A-Fa-f][0-9A-Fa-f])/chr(hex($1))/eg;
	$text =~ s/=\r?\n//sg;
	return $text;
}
