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

my $t = Test::Nginx->new()->has(qw/http/)->plan(3)
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
unlike(http_get('/disabled'), qr/X-Async-Time:/, 'disabled async handler');

###############################################################################
