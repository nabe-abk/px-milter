use strict;
#-------------------------------------------------------------------------------
# Mail Parser module
#							(C)2006-2026 nabe@abk
#-------------------------------------------------------------------------------
#
package Sakia::Net::MailParser;
our $VERSION = '1.22';
use Encode;
use MIME::Base64;
################################################################################
# base
################################################################################
sub new {
	my $class= shift;
	return bless({
		ROBJ		=> shift,
		__CACHE_PM	=> 1
	}, $class);
}

################################################################################
# parser main
################################################################################
sub parse {
	my $self = shift;
	my $ary  = shift;
	my $ROBJ = $self->{ROBJ};
	my $outcode = shift || $ROBJ->{SystemCode};

	if (!ref($ary)) {
		$ary = [ map { "$_\n" } split(/\r?\n/, $ary) ];
	}
	my $mail = $self->parse_mail_header($ary, $outcode);

	#-----------------------------------------------------------------------
	# parse addresses
	#-----------------------------------------------------------------------
	foreach(qw(from to cc replay)) {
		$mail->{$_ . '_list'} = $self->parse_address_list($mail->{$_});
	}

	#-----------------------------------------------------------------------
	# parse mail body
	#-----------------------------------------------------------------------
	my @parts;

	my $ctype = $mail->{content_type};
	if ($ctype =~ m|^multipart/(\w+)|i) {
		$self->{DEBUG} && $ROBJ->debug("*** mail is multipart ***");

		@parts = $self->parse_part($ary, $ctype, $outcode);

	} else {
		#---------------------------------------------------------------
		# simple
		#---------------------------------------------------------------
		$self->{DEBUG} && $ROBJ->debug("*** mail is simple ***");

		my $text = join('', @$ary);
		push(@parts, {
			main	=> $ctype !~ m|^text/html|i,
			type	=> $ctype,
			data	=> $self->decode_part_body($text, $ctype, $mail->{content_transfer_encoding})
		});
	}

	foreach(@parts) {
		my $type = $_->{type};
		if ($type =~ m|^text/|i) {
			$_->{charset} = ($type =~ /;\s*charset="(.*?)"/i || $type =~ /;\s*charset=([^\s;]*)/i) ? $1 : 'UTF-8';
		}
		$_->{size}  = length($_->{data});
		$_->{_type} = $type =~ s/;.*//r;

		if ($self->{DEBUG}) {
			my $msg='';
			foreach my $t (qw(_type encode charset filename size inline cid)) {
				if (!exists($_->{$t})) { next; }
				$msg .= " $t=$_->{$t}";
			}
			$ROBJ->debug("Part:$msg");	# debug-safe
		}
	}

	#-----------------------------------------------------------------------
	# Choice the main text
	#-----------------------------------------------------------------------
	my @inlines;
	my @attaches;
	$mail->{inlines}  = \@inlines;
	$mail->{attaches} = \@attaches;

	foreach(@parts) {
		if ($_->{inline}) {
			push(@inlines, $_);
			next;
		}

		if (exists($_->{filename})) {
			push(@attaches, $_);
			next;
		}
		if (!exists($mail->{body}) && ($_->{main} || $_->{type} =~ m|text/plain|)) {
			$mail->{body} = $_->{data};

			my $type = $_->{type};
			my $code = $_->{charset} || 'UTF-8';
			Encode::from_to($mail->{body}, $code, $outcode);
			next;
		}
		if (!exists($mail->{html}) && $_->{type} =~ m|text/html|) {
			$mail->{html}         = $_->{data};
			$mail->{html_charset} = $_->{charset};
			next;
		}
		push(@attaches, $_);
	}

	return $mail;
}

#-------------------------------------------------------------------------------
# parse multipart
#-------------------------------------------------------------------------------
sub parse_part {
	my $self    = shift;
	my $ary     = shift;
	my $ctype   = shift;
	my $outcode = shift;	# outcode
	my @parts   = $self->do_parse_part($ary, $ctype, $outcode);

	my @ary;
	foreach(@parts) {
		#
		# multipart/alternative is used when "text/plain" and "text/html" in parallel.
		# multipart/related is used when there is an image file of this html in "text/html".
		#
		if ($_->{type} =~ m|multipart/(\w+)|) {
			push(@ary, $self->parse_part([ split(/\n/, $_->{data}) ], $_->{type}, $outcode));
			next;
		}
		push(@ary, $_);
	}
	return @ary;
}

sub do_parse_part {
	my $self    = shift;
	my $ary     = shift;
	my $ctype   = shift;
	my $outcode = shift;

	if ($ctype !~ m!^multipart/\w+;\s*boundary=(?:"(.*?)"|([^\s]*))!i) {
		return;
	}
	my $boundary = "--$1$2";
	my $b1 = $boundary;
	my $b2 = "$boundary--";

	my @parts;
	while(@$ary) {
		my $x = shift(@$ary);
		$x =~ s/[\r\n]//g;
		if ($x ne $boundary && $x ne $b2) { next; }
		while(@$ary) {
			if ($ary->[0] =~ /^[\r\n]*$/) { shift(@$ary); next; }
			my $h      = $self->parse_mail_header($ary, $outcode);
			my $type   = $h->{content_type};
			my $dispos = $h->{content_disposition};
			my $encode = $h->{content_transfer_encoding};
			my $cid    = $h->{content_id} =~ /^<(.+)>$/ ? $1 : undef;

			my $part = {
				type	=> $type,
				encode	=> $encode,
				inline	=> $dispos =~ /^\s*inline\b/ ? 1 : 0,
				cid	=> $cid
			};
			push(@parts, $part);

			#  filename from Content-type
			my $ct = $self->parse_header_line( $type, $outcode );
			if (exists $ct->{name}) {
				$part->{filename} = $ct->{name};
			}
			# filename from Content-Disposition
			if ($dispos) {
				my $x = $self->parse_header_line( $dispos, $outcode );
				if (exists $x->{filename}) {
					$part->{filename} = $x->{filename};
				}
			}

			my $data = $self->read_until_boundary($ary, $boundary);
			$part->{data} = $self->decode_part_body($data, $type, $encode);
		}
	}
	return @parts;
}

################################################################################
# parser subroutine
################################################################################
#-------------------------------------------------------------------------------
# read until mutipart boundary
#-------------------------------------------------------------------------------
sub read_until_boundary {
	my ($self, $ary, $boundary, $encode) = @_;
	my $b2 = "$boundary--";
	my $data;
	while(@$ary) {
		my $x = shift(@$ary);
		$x =~ s/[\r\n]//g;
		if ($x eq $boundary || $x eq $b2) { last; }
		$data .= "$x\n";
	}
	return $data;
}

#-------------------------------------------------------------------------------
# decode body
#-------------------------------------------------------------------------------
sub decode_part_body {
	my ($self, $data, $type, $encode) = @_;
	$encode =~ tr/A-Z/a-z/;

	if ($encode eq 'base64') {
		return decode_base64($data);
	}
	if ($encode eq 'quoted-printable') {
		return $self->decode_quoted_printable($data);
	}
	return $self->decode_rfc3676($data, $type);
}

#-------------------------------------------------------------------------------
# parse mail header
#-------------------------------------------------------------------------------
sub parse_mail_header {
	my $self = shift;
	my $ary  = shift;
	my $code = shift;
	my $ROBJ = $self->{ROBJ};

	my %h;
	my ($n, $v);
	my @lines;
	while(@$ary) {
		my $x = shift(@$ary);
		$x =~ s/[\r\n]//g;
		if ($x =~ /^[ \t]+.*/) {
			# RFC 2822 FWS / RFC 2234 WSP
			$v .= "\n" . $x;
			next;
		} 
		if (defined $n) {
			if ($code) {
				$v = $self->decode_header_line($v, $code);
			}
			# save
			push(@lines, "$n: $v\n");
			$n     =~ tr/A-Z\-/a-z_/;
			$h{$n} = $v;
			$self->{DEBUG} && $ROBJ->debug("Header: $n=$v");
			undef $n;
		}
		# new header
		if ($x =~ /^([\w\-]+):\s*(.*)/) {
			$n = $1;
			$v = $2;
		}
		if ($x eq '') { last; }
	}
	$h{header} = join('', @lines);
	return \%h;
}

#-------------------------------------------------------------------------------
# address-list parser
#-------------------------------------------------------------------------------
sub parse_address_list {
	my $self = shift;
	my $line = shift;

	my @buf;
	$line =~ s/\x00//g;
	$line =~ s/"([^\"]*)"/push(@buf, $1), "\x00" . $#buf . "\x00"/eg;

	my @list;
	foreach(split(/\s*,\s*/, $line)) {
		if ($_ =~ /^\s*$/) { next; }
		if ($_ =~ /^(.*?)\s*<([\w\.\-]+\@[\w\.\-]+)>$/) {
			push(@list,{
				name	=> $1,
				address	=> $2
			});
		}
		if ($_ =~ /^\s*([\w\.\-]+\@[\w\.\-]+)\s*$/) {
			push(@list,{
				address	=> $1
			});
		}
	}
	foreach(@list) {
		$_->{name} =~ s/\x00(\d+)\x00/$buf[$1]/g;
	}

	return \@list;
}

################################################################################
# Base64 / RFC3676 / quoted-printable decoder
################################################################################
#-------------------------------------------------------------------------------
# decode for one line
#-------------------------------------------------------------------------------
sub decode_header_line {
	my $self = shift;
	my $line = shift;
	my $code = shift;

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

sub parse_header_line {		# RFC2231
	my $self = shift;
	my $line = shift;
	my $code = shift;

	# string
	my @str;
	$line =~ s/"(.*?)"/push(@str, $1), "\x00$#str\x00"/eg;

	my %h;
	foreach(split(/\s*;\s*/, $line)) {
		# string
		$_ =~ s/\x00(\d+)\x00/$str[$1]/g;
		if ($_ =~ /^\s*(.*?)=(.*?)\s*$/) {
			my $key = $1;
			my $val = $2;
			$key =~ tr/-/_/;
			if ($key =~ /^(.*?\*)\d+\*?$/) {
				$key = $1;
				$h{$key} .= $val;
			} else {
				$h{$key} = $val;
			}
		} elsif (!exists $h{_}) {
			$h{_} = $_;
		}
	}
	foreach(keys(%h)) {
		# RFC2231) filename*=iso-2022-jp''%1B%24B%3CL%3F%3F%1B%28B.jpg
		my $val = $h{$_};
		if ($_ =~ /^(.*?)\*$/) {
			my $key = $1;
			delete $h{$_};
			if ($val =~ /^(.*?)'.*?'(.*)$/) {
				my $val_code = $1;
				$val = $2;
				$val =~ s/%([0-9a-fA-F][0-9a-fA-F])/chr(hex($1))/eg;
				Encode::from_to($val, $val_code, $code);
			}
			$h{$key} = $val;
		} else {
			$h{$_} = $self->decode_header_line($val, $code);
		}
	}
	return \%h;
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

################################################################################
# other
################################################################################
sub parse_rfc_date {
	my $self = shift;	# Wed,  6 Jul 2022 00:48:15 +0900 (JST)
	my $rfc  = shift;	# Fri, 17 Jun 2022 01:32:20 +0900

	if ($rfc !~ /(\w\w\w),  ?(\d?\d) (\w\w\w) (\d\d\d\d) (\d\d):(\d\d):(\d\d)/) { return; }

	my $mon = index('JanFebMarAprMayJunJulAugSepOctNovDec', $3);
	if ($mon<0 || ($mon % 3)) { return; }

	return {
		YYYY	=> $4,
		MM	=> substr($mon/3 + 101, -2),
		DD	=> substr("0$2", -2),
		hh	=> $5,
		mm	=> $6,
		ss	=> $7
	};
}
sub rfc_date_to_ymd {
	my $self = shift;
	my $h    = $self->parse_rfc_date(@_);
	if (!$h) { return; }

	return "$h->{YYYY}-$h->{MM}-$h->{DD} $h->{hh}:$h->{mm}:$h->{ss}";
}

1;
