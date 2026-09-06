#!/usr/bin/perl

# (C) Nginx, Inc

# Tests for ngx-rust example modules.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http proxy http_ssl upstream_sticky/)
	->has_daemon('openssl')->plan(10);

my $sticky_header = $t->has_version('1.29.6') ? ' header' : '';
my $config = <<'EOF';

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    map $uri $upstream_connection {
        default  "";
        ~tls$    close;
    }

    upstream u {
        server 127.0.0.1:8081;
        custom 32;
    }

    upstream callbacks {
        server 127.0.0.1:8082;
        server 127.0.0.1:8083;
        sticky learn zone=callbacks:1m
                     create=$upstream_http_x_route lookup=$cookie_route%%STICKY_HEADER%%;
        custom 32;
        keepalive 4;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        error_log %%TESTDIR%%/e_debug.log debug;

        location = / {
            proxy_pass http://u;
        }

        location /callbacks/ {
            proxy_pass https://callbacks/;
            proxy_http_version 1.1;
            proxy_set_header Connection $upstream_connection;
            proxy_ssl_session_reuse on;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / { }
    }

    server {
        listen       127.0.0.1:8082 ssl;
        listen       127.0.0.1:8083 ssl;
        server_name  localhost;

        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;
        ssl_protocols TLSv1.2;
        ssl_session_cache builtin;

        add_header X-Route $server_port always;
        add_header X-Session $ssl_session_reused always;
        add_header X-Connection $connection always;
        add_header X-Connection-Requests $connection_requests always;

        location / {
            return 200;
        }
    }
}

EOF

$config =~ s/%%STICKY_HEADER%%/$sticky_header/;
$t->write_file_expand('nginx.conf', $config);
$t->write_file('openssl.conf', <<'EOF');
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for localhost: $!\n";

$t->write_file('index.html', '');
$t->run();

###############################################################################

like(http_get('/'), qr/200 OK/, 'custom upstream');

my $first = http_get('/callbacks/tls');
like($first, qr/200 OK.*X-Session: \./s, 'new upstream TLS session');

my $route = response_header($first, 'X-Route');
ok(defined $route, 'sticky route is published');

my $second = callback_get('/callbacks/tls', $route);
like($second, qr/200 OK/, 'second upstream TLS request');

SKIP: {
	skip 'no sticky header notification', 1 unless $sticky_header;

	is(response_header($second, 'X-Route'), $route,
		'header notification preserves the sticky peer');
}

like($second, qr/X-Session: r/, 'upstream TLS session is reused');

my $third = callback_get('/callbacks/keep', $route);
like($third, qr/200 OK/, 'persistent upstream request');
my $fourth = callback_get('/callbacks/keep', $route);

is(response_header($fourth, 'X-Connection'),
	response_header($third, 'X-Connection'), 'upstream keepalive hit');
is(response_header($fourth, 'X-Connection-Requests'),
	response_header($third, 'X-Connection-Requests') + 1,
	'upstream keepalive connection is redriven');

$t->stop();

SKIP: {
	skip "no --with-debug", 1 unless $t->has_module('--with-debug');

	like($t->read_file('e_debug.log'), qr/CUSTOM UPSTREAM request peer init/,
		'log - native request peer initializer');
}

###############################################################################

sub callback_get {
	my ($url, $route) = @_;

	return http(<<EOF);
GET $url HTTP/1.1
Host: localhost
Connection: close
Cookie: route=$route

EOF
}

sub response_header {
	my ($response, $name) = @_;

	return $1 if $response =~ /^\Q$name\E:\s*([^\r\n]+)/mi;
	return undef;
}

###############################################################################
