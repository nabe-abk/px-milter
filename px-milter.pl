#!/usr/bin/perl
#-------------------------------------------------------------------------------
my $LastUpdate = '2026.02.03';
################################################################################
# PX-Milter - Easy SPAM Mail Filter	   (C)2026 nabe@abk
#	https://github.com/nabe-abk/px-milter/
################################################################################
BEGIN {
	my $path = $0;
	$path =~ s|/[^/]*||;
	if ($path) { chdir($path); }
	unshift(@INC, './');
}
use strict;
use Fcntl;
use threads;

use Sakia::Net::MailParser;
use Sendmail::PMilter qw(:all);
eval {
	require Mail::SPF_XS;	# Required for SPF checks
};
################################################################################
my $DEBUG = 0;
my $PRINT = 1;
my $PORT  = 10025;
my $MODE;
my $MAX_BODY = 1024*1024;	# 1MB

my $USER_FILTER         = $0 =~ s|^.*/([\w\-\.]+)\.\w+$|$1.user-filter.pm|r;
my $USER_FILTER_PACKAGE = 'px_filter';

my $MILTER_NAME   = 'PX-Milter';
my $DETECT_HEADER = 'X-PX-Spam-Detect';
#-------------------------------------------------------------------------------
# Constant
#-------------------------------------------------------------------------------
my $SMFIP_SKIP = 0x00000400;
my $SMFIR_SKIP = 's';
my $SMFIP      = 0;		# Negociated milter protocol flags
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
		push(@ary, $x);
	}

	if ($HELP) {
		print STDERR <<HELP;	## safe
Usage: $0 [options]

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
&log("PX-Milter - Easy SPAM Mail Filter	 -- $LastUpdate");

if (!-e $USER_FILTER) {
	&log("Copy default user filter from $USER_FILTER.sample");
	system('cp', "$USER_FILTER.sample", $USER_FILTER);
}
&load_user_filter();

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
my $c_name;
my $c_ip;
my $c_host;
my $env_from;
my $rcpt_to;
my $msg_id;
my %header;
my $body = '';

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
	my $key = shift;
	my $val = $parser->decode_header_line(shift, 'utf8');

	$body .= "$key: $val\r\n";
	$key   =~ tr/A-Z/a-z/;

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

$cb{eoh} = sub {
	my $ctx = shift;
	$body .= "\r\n";

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

#-------------------------------------------------------------------------------
# Judgement
#-------------------------------------------------------------------------------
sub add_detect_header {
	my $ctx = shift;
	my $val = shift;
	&log("<$msg_id> Add \"$DETECT_HEADER: $val\"");

	if (ref($ctx) eq 'Sendmail::PMilter::Context') {
		$ctx->addheader($DETECT_HEADER, $val);
	}
}

$cb{eom} = sub {
	my $ctx = shift;
	my $to_name   = $header{to}   =~ s/\s*<.*//rs;	# remove <adr@dom>
	my $from_name = $header{from} =~ s/\s*<.*//rs;	#
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
	my $filter = &load_filter_function();
	if (!$filter) {
		&log("<$msg_id> Accept (filter load failed)");
		return SMFIS_CONTINUE;	# if error continue
	}
	my $arg = new arg_service({
		ctx	=> $ctx,
		c_name	=> $c_name,
		c_ip	=> $c_ip,
		c_host	=> $c_host,
		env_from=> $env_from,
		rcpt_to	=> $rcpt_to,
		msg_id  => $msg_id,
		to_name => $to_name,
		from_name=>$from_name,

		header	=> \%header,
		body	=> $mail->{body},
		html	=> $mail->{html},
		attaches=> $mail->{attaches}
	});

	my ($r, $reason, @reply) = &$filter($arg);
	my $ACCEPT	= px_filter::ACCEPT();		# load constant
	my $IS_SPAM	= px_filter::IS_SPAM();		#
	my $ADD_HEADER	= px_filter::ADD_HEADER();	#

	if ($r == $ACCEPT) {
		&add_detect_header($ctx, "no");
		return SMFIS_CONTINUE;	# Accept
	}

	#-------------------------------------------------------------
	# detect SPAM
	#-------------------------------------------------------------
	if ($reason eq '') { $reason = 'no reason'; }

	&log("<$msg_id> is SPAM ($reason)");

	my $res = ($r == $IS_SPAM) ? ($MODE // $ADD_HEADER) : $r;

	if ($res == $ADD_HEADER) {
		&add_detect_header($ctx, "yes ($reason)");
		return SMFIS_CONTINUE;
	}

	&log("<$msg_id> " . &get_smfis_code_name($res));

	if ($res == SMFIS_REJECT && @reply) {
		if (ref($ctx) eq 'Sendmail::PMilter::Context') {
		        $ctx->setreply(550, @reply);
		}
	}

	return $res;
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

		print "[$type] " . &get_smfis_code_name($r) . "\n";
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

	$SIG{PIPE} = 'IGNORE';

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
# subroutine for user_filter
################################################################################
package arg_service;
sub new {
	my $class = shift;
	return bless(shift, $class);
}

sub check_spf {
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
	my $ctx = $arg->{ctx};

	&main::log("<$msg_id> Add \"$key: $val\"");

	if (ref($ctx) eq 'Sendmail::PMilter::Context') {
		$ctx->addheader($key, $val);
	}
}
