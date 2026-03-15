#!/usr/bin/env perl
################################################################################
# Log-Viewer REST-API v1.3.2 (asynchron) - hardened patch
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
use Mojo::Util  qw(secure_compare decode);

umask 0007;

our $VERSION = '1.3.2';

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

my $listen    = $Config->{listen}        // '127.0.0.1:5005';
my $https     = $Config->{https}         // 0;
my $ssl_cert  = $Config->{ssl_cert_file} // '';
my $ssl_key   = $Config->{ssl_key_file}  // '';
my $LOGFILE   = $Config->{logfile}       // '/var/log/logviewer.log';

# Token nur aus ENV
my $api_token        = $ENV{API_TOKEN};
my $allow_no_token   = $Config->{allow_no_token}   ? 1 : 0;
my $expose_log_paths = $Config->{expose_log_paths} ? 1 : 0;

my $logdirs = $Config->{logdirs} or die "logdirs fehlt in Config!";
die "logdirs muss ein HASH sein!" unless ref($logdirs) eq 'HASH';

my @acl_cidrs = @{ $Config->{allowed_ips} // ['127.0.0.1'] };

# CORS restriktiver
my $cors_enabled = $Config->{cors_enabled} ? 1 : 0;
my @cors_origins = @{ $Config->{cors_allowed_origins} // [] };

# Proxy Vertrauen nur wenn explizit aktiviert
my $trust_proxy = $Config->{trust_proxy} ? 1 : 0;
my @trusted_proxies = @{ $Config->{trusted_proxies} // [] };

# Grenzen
my $default_lines = $Config->{default_lines} // 2000;
my $min_lines     = $Config->{min_lines}     // 10;
my $max_lines     = $Config->{max_lines}     // 50000;

$default_lines = 2000  if $default_lines !~ /^\d+$/ || $default_lines < 1;
$min_lines     = 10    if $min_lines !~ /^\d+$/     || $min_lines < 1;
$max_lines     = 50000 if $max_lines !~ /^\d+$/     || $max_lines < $min_lines;

# ------------------ Logging ------------------
my $log = Mojo::Log->new(level => 'info', path => $LOGFILE);

if (!$allow_no_token) {
  die "API_TOKEN fehlt in ENV und allow_no_token ist nicht aktiviert!"
    unless defined $api_token && length $api_token;
} else {
  $log->warn('API_TOKEN nicht gesetzt, Zugriff nur ueber IP ACL geschuetzt')
    unless defined $api_token && length $api_token;
}

# ------------------ Pfade vorbereiten (realpath) ------------------
my %LOGBASE; # name => abs+real path string
for my $name (sort keys %$logdirs) {
  next unless defined $name && length $name;

  my $entry = $logdirs->{$name};
  die "Logdir-Eintrag fuer $name ist ungueltig" unless ref($entry) eq 'HASH';

  my $p = $entry->{path} // '';
  die "Logdir $name hat keinen Pfad" unless length $p;

  my $abs  = path($p)->to_abs;
  my $real = eval { $abs->realpath };
  die "Logdir $name nicht zugänglich: $p" if $@ || !$real;
  die "Logdir $name ist kein Verzeichnis: $real" unless -d $real->to_string;

  $LOGBASE{$name} = $real->to_string;
}

# ------------------ Tail Binary prüfen ------------------
my @TAIL_CANDIDATES = ('/usr/bin/tail', '/bin/tail');
my $TAIL = '';

for my $cand (@TAIL_CANDIDATES) {
  if (-x $cand) {
    $TAIL = $cand;
    last;
  }
}

die "Kein sicheres tail Binary gefunden" unless $TAIL;

# ------------------ Helpers: JSON Antworten ------------------
sub _no_store {
  my ($c) = @_;
  $c->res->headers->header('Cache-Control' => 'no-store');
  $c->res->headers->header('Pragma'        => 'no-cache');
  $c->res->headers->header('X-Content-Type-Options' => 'nosniff');
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

# Immer JSON Fehler liefern, aber ohne rohe interne Fehlerdetails
app->hook(around_dispatch => sub {
  my ($next, $c) = @_;
  my $ok = eval { $next->(); 1 };
  return if $ok;

  my $err = $@ || 'Unknown error';
  $log->error("Unhandled exception: $err");

  return if $c->res->code && $c->res->body;

  $c->res->code(500);
  $c->res->headers->content_type('application/json; charset=UTF-8');
  _no_store($c);
  $c->render(json => { ok => 0, error => 'Internal server error' }, status => 500);
  return;
});

# ------------------ Helpers: Textdatei Check ------------------
my @TEXT_EXT = qw(.log .txt .conf .ini .out .err .csv .json .xml .syslog);

sub _has_allowed_text_extension {
  my ($file) = @_;
  return 0 unless defined $file && length $file;

  return 0 if $file =~ /\.(?:gz|zip|tar|bz2|xz|7z|exe|bin|jpg|png|jpeg|gif|pdf|html?)$/i;

  for my $ext (@TEXT_EXT) {
    return 1 if $file =~ /\Q$ext\E$/i;
  }

  return 0;
}

sub _looks_like_text {
  my ($file) = @_;
  return 0 unless defined $file && -f $file;

  open my $fh, '<:raw', $file or return 0;
  my $buf = '';
  my $read = read($fh, $buf, 4096);
  close $fh;

  return 0 unless defined $read;
  return 1 if $read == 0;

  return 0 if $buf =~ /\x00/;

  return 1;
}

sub is_textfile {
  my ($file) = @_;
  return 0 unless $file && -f $file;
  return 0 unless _has_allowed_text_extension($file);
  return 0 unless _looks_like_text($file);
  return 1;
}

# ------------------ Helpers: IP ACL (CIDR) ------------------
sub _ipv4_to_int {
  my ($ip) = @_;
  return undef unless defined $ip && $ip =~ /^(\d{1,3}\.){3}\d{1,3}$/;

  my @o = split /\./, $ip;
  for (@o) {
    return undef if $_ > 255;
  }

  return ($o[0] << 24) + ($o[1] << 16) + ($o[2] << 8) + $o[3];
}

sub ip_allowed {
  my ($ip, $cidrs_ref) = @_;
  $ip //= '';

  return 1 unless $cidrs_ref && ref($cidrs_ref) eq 'ARRAY' && @$cidrs_ref;

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

    if ($c =~ /^(\d{1,3}\.){3}\d{1,3}$/) {
      my $c_int = _ipv4_to_int($c);
      return 1 if defined $c_int && $c_int == $ip_int;
      next;
    }

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

sub _client_ip {
  my ($c) = @_;

  my $remote = $c->tx->remote_address // '';

  return $remote unless $trust_proxy;

  return $remote unless ip_allowed($remote, \@trusted_proxies);

  my $xff = $c->req->headers->header('X-Forwarded-For') // '';
  return $remote unless length $xff;

  my ($first) = split /\s*,\s*/, $xff;
  return length($first // '') ? $first : $remote;
}

# ------------------ Tail ohne Shell, UTF-8 Decode ------------------
sub slurp_tail_utf8 {
  my ($lines, $file) = @_;
  $lines //= $default_lines;

  my $p = Mojo::Promise->new;
  return $p->reject("Kein File") unless defined $file && length $file;

  my $subprocess = Mojo::IOLoop->subprocess;

  $subprocess->run(
    sub {
      open(my $fh, "-|:raw", $TAIL, "-n", "$lines", "--", $file)
        or die "tail failed: $!";

      local $/;
      my $raw = <$fh>;
      close $fh;

      my $text = eval { decode('UTF-8', $raw) };
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

  return unless $cors_enabled;

  my $origin = $c->req->headers->origin // '';
  my $allow_origin = '';

  if (@cors_origins) {
    for my $o (@cors_origins) {
      next unless defined $o && length $o;
      if ($origin eq $o) {
        $allow_origin = $o;
        last;
      }
    }
  }

  return unless length $allow_origin;

  $c->res->headers->header('Vary'                         => 'Origin');
  $c->res->headers->header('Access-Control-Allow-Origin'  => $allow_origin);
  $c->res->headers->header('Access-Control-Allow-Headers' => 'X-API-Token, Content-Type');
  $c->res->headers->header('Access-Control-Allow-Methods' => 'GET, OPTIONS');
});

options '/*' => sub {
  my $c = shift;
  _no_store($c);
  $c->render(text => '', status => 204);
};

# ------------------ Auth/ACL ------------------
hook before_dispatch => sub {
  my $c = shift;

  my $ip = _client_ip($c);

  if (@acl_cidrs) {
    unless (ip_allowed($ip, \@acl_cidrs)) {
      $log->warn("Verbotener Zugriff von IP $ip");
      return fail_json($c, "Forbidden access", 403);
    }
  }

  if (defined $api_token && length $api_token) {
    my $token = $c->req->headers->header('X-API-Token') // '';
    unless (length($token) && secure_compare($token, $api_token)) {
      $log->warn("Unauthorized access attempt from IP $ip");
      return fail_json($c, "Unauthorized", 401);
    }
  } elsif (!$allow_no_token) {
    $log->error("Sicherheitsfehler: API_TOKEN fehlt waehrend Laufzeit");
    return fail_json($c, "Server authentication misconfiguration", 500);
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

    push @routes_list, {
      method => $method_str,
      path   => $route->to_string,
    };
  }

  @routes_list = sort { $a->{path} cmp $b->{path} } @routes_list;

  success_json($c, {
    name          => 'Log-Viewer REST-API',
    version       => $VERSION,
    api_endpoints => \@routes_list,
  });
};

get '/logdirs' => sub {
  my $c = shift;

  my @list;
  for my $name (sort keys %$logdirs) {
    my $entry = { name => $name };
    if ($expose_log_paths) {
      $entry->{path} = $logdirs->{$name}{path};
    }
    push @list, $entry;
  }

  success_json($c, { logdirs => \@list });
};

get '/log/:name' => sub {
  my $c    = shift;
  my $name = $c->stash('name');

  $logdirs->{$name}
    or return fail_json($c, "Unbekanntes Logverzeichnis: $name", 404);

  my $base_abs = $LOGBASE{$name}
    // return fail_json($c, "Pfad nicht zugänglich: $name", 500);

  my $dir = path($base_abs);
  return fail_json($c, "Kann Verzeichnis nicht oeffnen", 500)
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
  } or return fail_json($c, "Kann Verzeichnis nicht lesen", 500);

  $log->info("Logliste fuer $name an " . (_client_ip($c) // '?'));
  success_json($c, { files => \@files, dir => $name });
};

# Route Struktur kompatibel lassen
get '/log/*name/*file' => sub {
  my $c    = shift;
  my $name = $c->stash('name');
  my $file = $c->stash('file') // '';
  $file =~ s{^[\/]+}{};

  $logdirs->{$name}
    or return fail_json($c, "Unbekanntes Logverzeichnis: $name", 404);

  my $base_abs = $LOGBASE{$name}
    // return fail_json($c, "Pfad nicht zugänglich: $name", 500);

  if ($file =~ m{(^|/)\.\.(/|$)} || $file =~ m{^\s*$}) {
    $log->warn("Directory-Traversal/illegaler Name: $file");
    return fail_json($c, "Illegaler Dateiname", 400);
  }

  # Zusätzliche Härtung gegen Steuerzeichen
  if ($file =~ /[\x00-\x1F\x7F]/) {
    $log->warn("Kontrollzeichen im Dateinamen: $file");
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
    return fail_json($c, "Zugriff verweigert", 403);
  }

  unless (is_textfile($full_real_s)) {
    $log->warn("Dateityp verweigert: $full_real_s");
    return fail_json($c, "Dateityp nicht erlaubt: $file", 400);
  }

  my $lines = $c->param('lines');
  $lines = $default_lines unless defined $lines && length $lines;
  $lines = int($lines);
  $lines = $min_lines if $lines < $min_lines;
  $lines = $max_lines if $lines > $max_lines;

  $c->render_later;

  slurp_tail_utf8($lines, $full_real_s)->then(sub {
    my ($text) = @_;
    $c->res->headers->content_type('text/plain; charset=UTF-8');
    _no_store($c);
    $c->render(text => $text);
  })->catch(sub {
    my ($err) = @_;
    $log->error("Fehler beim Lesen von $full_real_s: $err");
    _no_store($c);
    $c->render(json => { ok => 0, error => "Fehler beim Lesen" }, status => 500);
  });

  return;
};

any '/*whatever' => sub {
  my $c = shift;
  my $path = $c->req->url->path->to_string;
  $log->warn("Unbekannte Route: " . $c->req->method . " " . $path);
  fail_json($c, "Unbekannte Route", 404);
};

# ------------------ App Start: HTTP/HTTPS ------------------
my $listen_url;
if ($https && $ssl_cert && $ssl_key) {
  die "SSL Zertifikat nicht lesbar: $ssl_cert" unless -f $ssl_cert;
  die "SSL Key nicht lesbar: $ssl_key"        unless -f $ssl_key;

  $listen_url = "https://$listen?cert=$ssl_cert&key=$ssl_key";
  $log->info("Starte App im HTTPS-Modus: $listen");
} else {
  $listen_url = "http://$listen";
  $log->warn("Starte App im HTTP-Modus: $listen");
}

app->start('daemon', '-l', $listen_url);
