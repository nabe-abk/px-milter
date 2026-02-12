#!/usr/bin/perl
#-------------------------------------------------------------------------------
my $LastUpdate = '2026.02.12';
################################################################################
# EZ-Milter - Easy SPAM Mail Filter	   (C)2026 nabe@abk
#	https://github.com/nabe-abk/ez-milter/
################################################################################
use v5.14;
use strict;
BEGIN {
	my $path = $0;
	$path =~ s|/[^/]*||;
	if ($path) { chdir($path); }
	unshift(@INC, './');
}
use Fcntl;
use threads;

use Time::HiRes;
use Sakia::Net::MailParser;
use Sendmail::PMilter qw(:all);
eval {
	require Mail::SPF_XS;		# Required for SPF checks
};
eval {
	require IO::Socket::IP;		# Required try_connect() function
};

################################################################################
my $DEBUG = 0;
my $PRINT = 1;
my $PORT  = 10025;
my $MODE;
my $MAX_BODY = 1024*1024;	# 1MB

my $USER_FILTER         = $0 =~ s|^.*/([\w\-\.]+)\.\w+$|$1.user-filter.pm|r;
my $USER_FILTER_PACKAGE = 'user_filter';

my $MILTER_NAME   = 'EZ-Milter';
my $DETECT_HEADER = 'X-EZ-Spam-Detect';
#-------------------------------------------------------------------------------
# Constant
#-------------------------------------------------------------------------------
my $SMFIP_SKIP = 0x00000400;
my $SMFIR_SKIP = 's';
my $SMFIP      = 0;		# Negociated milter protocol flags

# Load from user_filter in load_user_filter()
my $ACCEPT;
my $NO_CHECK;
my $IS_SPAM;
my $ADD_HEADER;
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

		if ($x eq '-pass')    { $MODE = undef; next; }
		if ($x eq '-reject')  { $MODE = SMFIS_REJECT;  next; }
		if ($x eq '-discard') { $MODE = SMFIS_DISCARD; next; }

		if ($x eq '-p') {
			$PORT = int(shift(@ARGV));
			next;
		}
		if ($x eq '-m') {
			$MAX_BODY = int(shift(@ARGV) * 1024*1024);
			next;
		}
		if ($x eq '-t') {
			$TEST_FILE = shift(@ARGV);
			next;
		}
		if ($x =~ /.+\.eml$/i) {
			$TEST_FILE = $x;
			next;
		}
		push(@ary, $x);
	}

	if ($HELP) {
		print STDERR <<HELP;	## safe
Usage: $0 [options] [test-file.eml]

Available options are:
  -p port	bind port number (default: 10025)
  -t file.eml	milter test mode
  -m size	maximum email size to analyze [MB] (default: 1)
  -s		silent mode
  -d		debug mode
  -h		view this help

[Run modes]
  -pass		Add "$DETECT_HEADER: yes (reason)" to header (default)
  -reject	REJECT  mode
  -discard	DISCARD mode
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
&log("EZ-Milter - Easy SPAM Mail Filter	 --- $LastUpdate (C)nabe\@abk");
&log("Default mode: " . ($MODE ?  &get_smfis_code_name($MODE) : "Add '$DETECT_HEADER' header"));

if (!-e $USER_FILTER) {
	&log("Copy default user filter from $USER_FILTER.sample");
	system('cp', "$USER_FILTER.sample", $USER_FILTER);
}
if (&load_user_filter()) {
	exit;
}

my $parser = new Sakia::Net::MailParser({});

#-------------------------------------------------------------------------------
# Patch to Sendmail::PMilter::Context
#-------------------------------------------------------------------------------
# To improve throughput.
#
my $send_SMFIR_SKIP;
if (1) {
	require Sendmail::PMilter::Context;
	*Sendmail::PMilter::Context::write_packet
	= sub {
		my $this = shift;
		my $code = shift;
		my $out  = shift // '';
		if (($SMFIP & SMFIP_SKIP) && $send_SMFIR_SKIP) {
			$code = $SMFIR_SKIP;
			$out  = '';
			$send_SMFIR_SKIP = 0;
		}
		my $len  = pack('N', length($out) + 1);

		$this->{socket}->syswrite($len . $code . $out);
		return $len;
	};
}

#-------------------------------------------------------------------------------
# Regist callback
#-------------------------------------------------------------------------------
# callback types: close connect helo abort envfrom envrcpt header eoh eom
#
my %cb;
my $cb_type;

my $arg;
my %header;
my $body;
my $pre_DATA;

$cb{negotiate} = sub {
	my $ctx   = shift;
	my $r_ver = shift;	# milter_protocol_version_ref
	my $r_act = shift;	# actions_available_ref
	my $r_pro = shift;	# protocol_steps_available_ref

	$SMFIP = ($$r_pro &= (SMFIP_DEFAULTS | $SMFIP_SKIP));

	return SMFIS_CONTINUE;
};

$cb{helo} = sub {
	my $ctx = shift;
	#
	# undef, because multiple message can be sent over the same connection.
	#
	undef %header;
	$arg = new arg_service({
		ctx	=> $ctx,	# use by add_header() for user filter
		header	=> \%header
	});
	$body     = '';
	$pre_DATA =  1;
	#{
        #	daemon_addr => '192.168.0.10',
        #	daemon_name => 'my.example.jp',
        #	v           => 'Postfix 3.10.5',
        #	j           => 'sender_name.example.jp',
        #	_           => 'lookup_host_name [client ip]',
        #};
	eval {
		my $c = $ctx->{symbols}->{C};
		$arg->{c_name} = $c->{j};
		if ($c->{_} =~ /^([^\s]*)\s\[(.*)\]/) {
			$arg->{c_ip}   = $2;
			$arg->{c_host} = $1;	# lookup name
		}
	};
	$DEBUG && print "client name:   $arg->{c_name}\n";
	$DEBUG && print "client adress: $arg->{c_ip}\n";
	$DEBUG && print "client host:   $arg->{c_host}\n";

	return SMFIS_CONTINUE;
};
$cb{envfrom} = sub {
	my $ctx = shift;
	$arg->{env_from} = shift =~ s/^<(.*)>$/$1/r;
	$DEBUG && print "MAIL FROM: $arg->{env_from}\n";

	return SMFIS_CONTINUE;
};
$cb{envrcpt} = sub {
	my $ctx = shift;
	$arg->{rcpt_to} = shift =~ s/^<(.*)>$/$1/r;
	$DEBUG && print "RCPT TO:   $arg->{rcpt_to}\n";

	my $r = &call_user_filter($ctx, 'check_pre_DATA');
	if ($r != SMFIS_CONTINUE) {
		$pre_DATA = 0;
	}
	return $r;
};

$cb{data} = sub {
	my $ctx = shift;
	$pre_DATA = 0;

	$DEBUG && print "DATA command\n";
	return SMFIS_CONTINUE;
};

$cb{header} = sub {
	my $ctx = shift;
	my $key = shift;
	my $val = $parser->decode_header_line(shift, 'utf8');

	$body .= "$key: $val\r\n";
	$key   =~ tr/A-Z/a-z/;

	if (!exists($header{$key})) {
		$header{$key} = $val;
	}

	return SMFIS_CONTINUE;
};

$cb{eoh} = sub {
	my $ctx = shift;
	$body .= "\r\n";

	$DEBUG && print "End of header\n";
	return SMFIS_CONTINUE;
};

$cb{body} = sub {
	my $ctx = shift;
	my $add = shift;
	my $len = shift;

	if (length($body) < $MAX_BODY) {
		$body .= $add;
	}
	if ($MAX_BODY < length($body)) {
		$send_SMFIR_SKIP = 1;	# Skip subsequent body callbacks
	}

	return SMFIS_CONTINUE;
};

$cb{quit} = sub {
	my $ctx = shift;
	if ($pre_DATA && $arg->{rcpt_to}) {
		&log("Connection closed after RCPT TO and before DATA");
	}
	return SMFIS_CONTINUE;
};

#-------------------------------------------------------------------------------
# call user filter
#-------------------------------------------------------------------------------
my @add_header_buf;

$cb{eom} = sub {
	my $ctx = shift;

	#-------------------------------------------------------------
	# add header by buffer. addheader is only valid for "eom".
	#-------------------------------------------------------------
	foreach(@add_header_buf) {
		$ctx->addheader($_->{key}, $_->{val});
	}
	undef @add_header_buf;

	#-------------------------------------------------------------
	# parse mail data
	#-------------------------------------------------------------
	my $to_name   = $header{to}   =~ m|(.*)\s*<.*| ? $1 : '';	# remove <adr@dom>
	my $from_name = $header{from} =~ m|(.*)\s*<.*| ? $1 : '';	#
	$to_name   =~ s/^"([^"]*)"$/$1/;		# dequote
	$from_name =~ s/^"([^"]*)"$/$1/;		#
	$DEBUG && print "To name:   $to_name\n";
	$DEBUG && print "From name: $from_name\n";

	# use Sakia::Net::MailParser.pm
	my $mail = $parser->parse("$body\n", 'utf8');
	if ($mail->{html} && $mail->{html_charset}) {
		Encode::from_to($mail->{html}, $mail->{html_charset}, 'utf8');
		$mail->{html_charset} = 'utf8';
	}

	if ($DEBUG) {
		if ($mail->{body}) {
			print "[text]\n$mail->{body}";
		}
		if ($mail->{html}) {
			print "[html]\n$mail->{html}";
		}
		foreach(@{$mail->{attaches}}) {
			print "attach: \"$_->{filename}\" $_->{type} $_->{size} bytes\n";
		}
	}

	#-------------------------------------------------------------
	# call user filter
	#-------------------------------------------------------------
	$arg->{to_name}   = $to_name;
	$arg->{from_name} = $from_name;
	$arg->{body}      = $mail->{body};
	$arg->{html}      = $mail->{html};
	$arg->{attaches}  = $mail->{attaches};

	return &call_user_filter($ctx);
};

sub call_user_filter {
	my $ctx   = shift;
	my $fname = shift;
	my $main_mode = $fname eq '' || $fname eq 'main';

	my $filter = &load_filter_function($fname);
	if (!$filter) {
		if ($main_mode) {
			&log("Accept (filter load failed)");
		}
		return SMFIS_CONTINUE;	# no filter
	}
	my ($r, $reason, @reply) = &$filter($arg);

	if ($main_mode) {
		if ($r == $ACCEPT) {
			&add_header($ctx, $DETECT_HEADER, "no");
			return SMFIS_CONTINUE;	# Accept
		}
		if ($r == $NO_CHECK) {
			&add_header($ctx, $DETECT_HEADER, "no check");
			return SMFIS_CONTINUE;	# Accept
		}

	} else {
		if ($r==$ACCEPT) {
			return SMFIS_CONTINUE;	# Continue
		}
		if ($r==$NO_CHECK || $r==$IS_SPAM || $r==$ADD_HEADER) {
			&log("Illegal return value (NO_CHECK or IS_SPAM or ADD_HEADER) on check_pre_DATA()");
			return SMFIS_CONTINUE;
		}
	}

	#-------------------------------------------------------------
	# detect SPAM
	#-------------------------------------------------------------
	if ($reason eq '') { $reason = 'no reason'; }

	my $res = ($r == $IS_SPAM) ? ($MODE // $ADD_HEADER) : $r;

	if ($res == $ADD_HEADER) {
		&add_header($ctx, $DETECT_HEADER, "yes ($reason)");
		return SMFIS_CONTINUE;	# Accept
	}

	&log(&get_smfis_code_name($res) . " ($reason)");

	if ($res == SMFIS_REJECT && @reply) {
		if (ref($ctx) eq 'Sendmail::PMilter::Context') {
		        $ctx->setreply(550, @reply);
		}
	}

	return $res;
}

sub add_header {
	my $ctx = shift;
	my $key = shift;
	my $val = shift;
	&log("Add \"$key: $val\"");

	if (ref($ctx) eq 'Sendmail::PMilter::Context') {
		if ($ctx->{cb} eq 'eom') {
			$ctx->addheader($key, $val);
		} else {
			push(@add_header_buf, { key=>$key, val=>$val });
		}
	}
}

#-------------------------------------------------------------------------------
# Start
#-------------------------------------------------------------------------------
if ($TEST_FILE eq '') {
	my $milter = new Sendmail::PMilter;

	&log("Bind localhost:$PORT");
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
		if ($x =~ /^\r?\n$/) { last; }

		while(@$lines && $lines->[0] =~ /^[\t ]+/) {
			$x .= shift(@$lines);
		}
		push(@header, $x);
	}

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

		print &get_smfis_code_name($r) . "\n";
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

	my $CHUNK = 64*1024;
	my $data  = join('', @$lines);
	while($data ne '') {
		my $buf = substr($data,      0, $CHUNK);
		$data   = substr($data, $CHUNK);

		&callback('body', $buf, length($buf));
		if ($send_SMFIR_SKIP) { last; }
	}
	&callback('eom');
	&callback('quit');

	print "ACCEPT\n";
}
exit(0);


################################################################################
# dispacher and Milter function
################################################################################
sub get_ithreads {
	return $#{[ threads->list() ]}+1;
}
my $in_THREAD;
sub my_dispatcher {		# "$this" is obj of Sendmail::PMilter
	my $this    = shift;
	my $srv     = shift;
	my $handler = shift;
	my $max_ths = $this->get_max_interpreters();

	$SIG{PIPE} = 'IGNORE';

	my $thread_main = sub {
		my $sock = shift;
		$in_THREAD = 1;

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

sub get_smfis_code_name {
	my $c = shift;
	if ($c == SMFIS_REJECT)   { return "REJECT";   }
	if ($c == SMFIS_DISCARD)  { return "DISCARD";  }
	if ($c == SMFIS_ACCEPT)   { return "ACCEPT";   }
	if ($c == SMFIS_TEMPFAIL) { return "TEMPFAIL"; }
	if ($c == SMFIS_MSG_LOOP) { return "MSG_LOOP"; }
	if ($c == SMFIS_ALL_OPTS) { return "ALL_OPTS"; }
	return 'UNKNOWN';
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
		return 1;
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
			return 10;
		}
		my $re = $user_filter_timestamp ? "re" : '';
		$user_filter_size      = $size;
		$user_filter_timestamp = $mod;
		&log("User filter ${re}load: last modified=" . &get_timestamp($mod) . " / size=$size");
	}
	{
		# Load constants
		no strict 'refs';
		$ACCEPT     = &{$USER_FILTER_PACKAGE . '::ACCEPT'    }();
		$NO_CHECK   = &{$USER_FILTER_PACKAGE . '::NO_CHECK'  }();
		$IS_SPAM    = &{$USER_FILTER_PACKAGE . '::IS_SPAM'   }();
		$ADD_HEADER = &{$USER_FILTER_PACKAGE . '::ADD_HEADER'}();
	}
	return 0;
}

sub load_filter_function {
	my $name = shift || 'main';
	no strict 'refs';
	return *{$USER_FILTER_PACKAGE . '::' . $name}{CODE};
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

	my $from = $arg->{env_from} ne '' ? " from=<$arg->{env_from}>" : '';
	my $to   = $arg->{rcpt_to}  ne '' ? " to=<$arg->{rcpt_to}>"    : '';

	local($|) = 1;
	my $head = $in_THREAD ? "ip=<$arg->{c_ip}>$from$to " : '';
	print "$ts $head$msg\n";
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
# subroutine for user_filter
################################################################################
package arg_service;
sub new {
	my $class = shift;
	my $self  = shift;
	$self->{can_check_spf} = $Mail::SPF_XS::VERSION;
	return bless($self, $class);
}

sub check_spf {
	my $arg = shift;
	if ($arg->{_spf_result}) { return $arg->{_spf_result} };
	return ( $arg->{_spf_result} = $arg->do_check_spf(@_) );
}
sub do_check_spf {
	my $arg = shift;
	my $spf = Mail::SPF_XS::Server->new({});
	my $req = Mail::SPF_XS::Request->new({
		identity        => $arg->{env_from},
		ip_address      => $arg->{c_ip}
	});
	my $result = $spf->process($req);
	#
	# SPF_strresult() in https://github.com/shevek/libspf2/blob/master/src/libspf2/spf_utils.c
	#
	my $code = $result->code;
	return ($code eq 'pass' || $code eq 'fail' || $code eq 'softfail') ? $code : 'none';
}

sub add_header {
	my $arg = shift;
	my $key = shift;
	my $val = shift;
	&main::add_header($arg->{ctx}, $key, $val);
}

sub log {
	my $arg = shift;
	&main::log(@_);
}

sub try_connect {
	my $arg  = shift;
	my $ip   = shift;
	my $port = shift;
	my $timeout = shift || 5;

	if (! $IO::Socket::IP::VERSION) {
		&main::log("IO::Socket::IP is not found in try_connect()");
		return;
	};
	*IO::Socket::IP::read_line = \&_read_line_for_IO_Socket;

	return IO::Socket::IP->new(
		PeerHost => $ip,
		PeerPort => $port,
		Proto    => 'tcp',
		Timeout  => $timeout
	);
}

sub _read_line_for_IO_Socket {
	my $sock    = shift;
	my $timeout = shift;
	if (!$timeout) {
		return (my $x = <$sock>);
	}

	my $vec='';
	vec($vec, fileno($sock), 1)=1;
	my $blocking = $sock->blocking(0);
	$sock->blocking(0);

	my $t0  = [Time::HiRes::gettimeofday()];
	my $line='';
	LOOP: while(1) {
		my $remain = $timeout - Time::HiRes::tv_interval($t0);
		if ($remain <= 0) { last; }

		select(my $rvec=$vec, undef, my $evec=$vec, $remain);
		if ($evec eq $vec) { last; }		# error

		my $bytes=0;
		while(1) {
			$sock->recv(my $x, 1);
			if ($x eq '') { last; }
			$line .= $x;
			$bytes++;
			if ($x eq "\n") { last LOOP; }
		}
		if (!$bytes) { last; }
	}
	$sock->blocking($blocking);
	return $line;
}
