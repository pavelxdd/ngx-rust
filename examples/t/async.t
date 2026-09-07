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

my $thread_wake = $^O ne 'MSWin32';
my $t = Test::Nginx->new()->has(qw/http/)->plan(9 + $thread_wake)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            async on;
        }

        location /disabled {
            async off;
        }

        location = /async-target {
            internal;
            async off;
            return 204;
        }
    }
}

EOF

$t->write_file('index.html', '');
$t->run();

###############################################################################

my $response = http_get('/index.html');
like($response, qr/X-Async-Time:/, 'async handler');
like($response, qr/X-Async-Subrequest-Status: 204/, 'async subrequest');
like($response, qr/X-Async-Thread-Wake: 1/, 'async thread wake') if $thread_wake;
unlike(http_get('/disabled'), qr/X-Async-Time:/, 'disabled async handler');
like($t->read_file('error.log'), qr/async log facade initialized/, 'log facade');

$t->stop();
my $log = $t->read_file('error.log');
like($log, qr/async companion task executed/, 'second module task');
like($log, qr/async primary scheduler lease released/, 'primary module released scheduler');
like($log, qr/async companion scheduler lease released/, 'companion module released scheduler');
my @final_releases = $log =~ /async (?:primary|companion) scheduler lease released, stopped=true/g;
is(scalar @final_releases, 1, 'scheduler stopped by final module only');
unlike($log, qr/(?:open socket #[0-9]+ left|aborting)/, 'process exit quiesced async resources');

###############################################################################
