#!/usr/bin/env perl
################################################################################
# Log-Viewer REST-API v1.3.1 (asynchron) - ultra-clean
################################################################################

use strict;
use warnings;
use utf8;
use open qw(:std :utf8);

use Mojolicious::Lite;
use Mojo::File  qw(path);
use Mojo::Log;
use Mojo::JSON  qw(decode_json);
use Mojo::Promise;
use Mojo::Util  qw(secure_compare);

umask 0007;

our $VERSION = '1.3.1';

# ------------------ Config laden (relativ zum Script) ------------------
my $BASE_DIR   = path(__FILE__)->dirname->to_abs;
my $configfile = $BASE_DIR->child('config.json');

die "Config $configfile fehlt!" unless -f $configfile->to_string;

my $Config = do {
  my $json_text = eval { $configfile->slurp };
  die "Config nicht lesbar: $@" if $@;

  my $cfg = eval { decode_json($json_text) };
  die "Config JSON ungueltig: $@" if $@ || ref($cfg) ne 'HASH';
  $cfg;
};

my $listen    = $Config->{listen}        // '0.0.0.0:5005';
my $https     = $Config->{https}         // 0;
my $ssl_cert  = $Config->{ssl_cert_file} // '';
my $ssl_key   = $Config->{ssl_key_file}  // '';
my $LOGFILE   = $Config->{logfile}       // '/var/log/logviewer.log';
my $api_token = $ENV{API_TOKEN};         # Token nur aus ENV (optional)

my $logdirs = $Config->{logdirs} or die "logdirs fehlt in Config!";
my @acl_cidrs = @{ $Config->{allowed_ips} // ['127.0.0.1'] };

# ------------------ Logging ------------------
my $log = Mojo::Log->new(level => 'info', path => $LOGFILE);

$log->warn('API_TOKEN nicht gesetzt !')
  unless defined $api_token && length $api_token;

# ------------------ Pfade vorbereiten (realpath) ------------------
my %LOGBASE; # name => abs+real path string
for my $name (sort keys %$logdirs) {
  my $p = $logdirs->{$name}{path} // next;
  my $abs  = path($p)->to_abs;
  my $real = eval { $abs->realpath };
  die "Logdir $name nicht zugänglich: $p" if $@ || !$real;
  die "Logdir $name ist kein Verzeichnis: $real" unless -d $real->to_string;
  $LOGBASE{$name} = $real->to_string;
}

# ------------------ Helpers: JSON Antworten ------------------
sub _no_store {
  my ($c) = @_;
  $c->res->headers->header('Cache-Control' => 'no-store');
  return;
}

sub fail_json {
  my ($c, $msg, $status) = @_;
  $status //= 400;
  $log->error($msg);
  _no_store($c);
  $c->render(json => { ok => 0, error => $msg }, status => $status);
  return;
}

sub success_json {
  my ($c, $data, $status) = @_;
  $status //= 200;
  $data->{ok} = 1 unless exists $data->{ok};
  _no_store($c);
  $c->render(json => $data, status => $status);
  return;
}

# Immer JSON Fehler liefern (kein HTML Exception Template)
app->hook(around_dispatch => sub {
  my ($next, $c) = @_;
  my $ok = eval { $next->(); 1 };
  return if $ok;

  my $err = $@ || 'Unknown error';
  $c->res->code(500);
  $c->res->headers->content_type('application/json; charset=UTF-8');
  $c->render(json => { ok => 0, error => "$err" });
  return;
});

# ------------------ Helpers: Textdatei Check ------------------
my @TEXT_EXT = qw(.log .txt .conf .ini .out .err .csv .json .xml .syslog);

sub is_textfile {
  my ($file) = @_;
  return 0 unless $file && -f $file;

  # harte Blockliste (Archive/Binaer/Images)
  return 0 if $file =~ /\.(gz|zip|tar|bz2|xz|7z|exe|bin|jpg|png|jpeg|pdf|html?)$/i;

  for my $ext (@TEXT_EXT) {
    return 1 if $file =~ /\Q$ext\E$/i;
  }

  # Fallback: wenn keine Extension passt, verweigern (Hardening)
  return 0;
}

# ------------------ Helpers: IP ACL (CIDR) ------------------
sub _ipv4_to_int {
  my ($ip) = @_;
  return undef unless defined $ip && $ip =~ /^(\d{1,3}\.){3}\d{1,3}$/;
  my @o = split /\./, $ip;
  for (@o) { return undef if $_ > 255 }
  return ($o[0] << 24) + ($o[1] << 16) + ($o[2] << 8) + $o[3];
}

sub ip_allowed {
  my ($ip, $cidrs_ref) = @_;
  $ip //= '';

  return 1 unless $cidrs_ref && ref($cidrs_ref) eq 'ARRAY' && @$cidrs_ref;

  # IPv6 very basic: exact match only
  if ($ip =~ /:/) {
    for my $c (@$cidrs_ref) {
      next unless defined $c;
      return 1 if $c eq $ip;
    }
    return 0;
  }

  my $ip_int = _ipv4_to_int($ip);
  return 0 unless defined $ip_int;

  for my $c (@$cidrs_ref) {
    next unless defined $c && length $c;

    # single IP
    if ($c =~ /^(\d{1,3}\.){3}\d{1,3}$/) {
      my $c_int = _ipv4_to_int($c);
      return 1 if defined $c_int && $c_int == $ip_int;
      next;
    }

    # CIDR
    if ($c =~ /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/) {
      my ($net, $masklen) = ($1, $2);
      next if $masklen < 0 || $masklen > 32;

      my $net_int = _ipv4_to_int($net);
      next unless defined $net_int;

      my $mask = $masklen == 0 ? 0 : (0xFFFFFFFF << (32 - $masklen)) & 0xFFFFFFFF;
      return 1 if (($ip_int & $mask) == ($net_int & $mask));
      next;
    }
  }

  return 0;
}

# ------------------ Tail ohne Shell, UTF-8 Decode ------------------
my $TAIL = -x '/usr/bin/tail' ? '/usr/bin/tail' : 'tail';

sub slurp_tail_utf8 {
  my ($lines, $file) = @_;
  $lines //= 2000;

  my $p = Mojo::Promise->new;
  return $p->reject("Kein File") unless defined $file && length $file;

  my $subprocess = Mojo::IOLoop->subprocess;

  $subprocess->run(
    sub {
      open(my $fh, "-|:raw", $TAIL, "-n", "$lines", $file)
        or die "tail failed: $!";

      local $/;
      my $raw = <$fh>;
      close $fh;

      my $text = eval { Mojo::Util::decode('UTF-8', $raw) };
      $text = $raw if $@;

      return $text;
    },
    sub {
      my ($subproc, $err, $text) = @_;
      if ($err) {
        my $msg = ref($err) ? "$err" : $err;
        return $p->reject($msg);
      }
      return $p->resolve($text // '');
    }
  );

  return $p;
}

# ------------------ CORS ------------------
app->hook(after_dispatch => sub {
  my $c = shift;
  $c->res->headers->header('Access-Control-Allow-Origin'  => '*');
  $c->res->headers->header('Access-Control-Allow-Headers' => 'X-API-Token, Content-Type');
  $c->res->headers->header('Access-Control-Allow-Methods' => 'GET, OPTIONS');
});

options '/*' => sub { shift->render(text => '', status => 204) };

# ------------------ Auth/ACL ------------------
hook before_dispatch => sub {
  my $c = shift;

  if (@acl_cidrs) {
    my $ip = $c->tx->remote_address // '';
    unless (ip_allowed($ip, \@acl_cidrs)) {
      $log->warn("Verbotener Zugriff von IP $ip");
      return fail_json($c, "Forbidden access from IP $ip", 403);
    }
  }

  # Token optional: nur pruefen, wenn gesetzt
  if (defined $api_token) {
    my $token = $c->req->headers->header('X-API-Token') // '';
    unless ($token && secure_compare($token, $api_token)) {
      $log->warn("Unauthorized access attempt");
      return fail_json($c, "Unauthorized access attempt", 401);
    }
  }

  return;
};

# ------------------ API Routes ------------------
get '/' => sub {
  my $c = shift;
  my @routes_list;

  for my $route (@{ app->routes->children }) {
    next unless ref $route;
    my $methods = $route->via;
    my $method_str = (ref($methods) eq 'ARRAY' && @$methods)
      ? join(', ', map { uc } @$methods)
      : 'ANY';
    push @routes_list, { method => $method_str, path => $route->to_string };
  }

  @routes_list = sort { $a->{path} cmp $b->{path} } @routes_list;

  $c->render(json => {
    ok            => 1,
    name          => 'Log-Viewer REST-API',
    version       => $VERSION,
    api_endpoints => \@routes_list,
  });
};

get '/logdirs' => sub {
  my $c = shift;
  my @list = map { { name => $_, path => $logdirs->{$_}{path} } } sort keys %$logdirs;
  success_json($c, { logdirs => \@list });
};

get '/log/:name' => sub {
  my $c    = shift;
  my $name = $c->stash('name');

  $logdirs->{$name} or return fail_json($c, "Unbekanntes Logverzeichnis: $name", 404);
  my $base_abs = $LOGBASE{$name} // return fail_json($c, "Pfad nicht zugänglich: $name", 500);

  my $dir = path($base_abs);
  return fail_json($c, "Kann Verzeichnis nicht oeffnen: $base_abs", 500)
    unless -d $dir->to_string;

  my @files;
  eval {
    for my $p ($dir->list->each) {
      my $full = $p->to_string;
      next unless -f $full;
      next if -l $full;
      next unless is_textfile($full);
      push @files, $p->basename;
    }
    1;
  } or return fail_json($c, "Kann Verzeichnis nicht lesen: $base_abs", 500);

  $log->info("Logliste fuer $name ($base_abs) an " . ($c->tx->remote_address // '?'));
  success_json($c, { files => \@files, dir => $name });
};

# Route Struktur kompatibel lassen
get '/log/*name/*file' => sub {
  my $c    = shift;
  my $name = $c->stash('name');
  my $file = $c->stash('file') // '';
  $file =~ s{^[\/]+}{};

  $logdirs->{$name} or return fail_json($c, "Unbekanntes Logverzeichnis: $name", 404);
  my $base_abs = $LOGBASE{$name} // return fail_json($c, "Pfad nicht zugänglich: $name", 500);

  if ($file =~ m{(^|/)\.\.(/|$)} || $file =~ m{^\s*$}) {
    $log->warn("Directory-Traversal/illegaler Name: $file");
    return fail_json($c, "Illegaler Dateiname", 400);
  }

  my $full   = path($base_abs)->child($file);
  my $full_s = $full->to_string;

  return fail_json($c, "Datei nicht gefunden: $file", 404) unless -f $full_s;
  return fail_json($c, "Symlinks sind nicht erlaubt", 400) if -l $full_s;

  my $full_real = eval { $full->realpath };
  return fail_json($c, "Pfad nicht aufloesbar", 500) if $@ || !$full_real;

  my $full_real_s = $full_real->to_string;

  my $base_prefix = $base_abs;
  $base_prefix =~ s{/\z}{};

  unless (index($full_real_s, $base_prefix . '/') == 0 || $full_real_s eq $base_prefix) {
    return fail_json($c, "Zugriff verweigert (ausserhalb Base)", 403);
  }

  unless (is_textfile($full_real_s)) {
    $log->warn("Dateityp verweigert: $full_real_s");
    return fail_json($c, "Dateityp nicht erlaubt: $file", 400);
  }

  my $lines = $c->param('lines') || 2000;
  $lines = int($lines);
  $lines = 10    if $lines < 10;
  $lines = 50000 if $lines > 50000;

  $c->render_later;

  slurp_tail_utf8($lines, $full_real_s)->then(sub {
    my ($text) = @_;
    $c->res->headers->content_type('text/plain; charset=UTF-8');
    _no_store($c);
    $c->render(text => $text);
  })->catch(sub {
    my ($err) = @_;
    $log->error("Fehler beim Lesen: $err");
    _no_store($c);
    $c->render(json => { ok => 0, error => "Fehler beim Lesen!" }, status => 500);
  });

  return;
};

any '/*whatever' => sub {
  my $c = shift;
  $log->warn("Unbekannte Route: " . $c->req->method . " " . $c->req->url->path);
  fail_json($c, "Unbekannte Route: " . $c->req->method . " " . $c->req->url->path, 404);
};

# ------------------ App Start: HTTP/HTTPS ------------------
my $listen_url;
if ($https && $ssl_cert && $ssl_key) {
  $listen_url = "https://$listen?cert=$ssl_cert&key=$ssl_key";
  $log->info("Starte App im HTTPS-Modus: $listen_url");
} else {
  $listen_url = "http://$listen";
  $log->info("Starte App im HTTP-Modus: $listen_url");
}

app->start('daemon', '-l', $listen_url);
