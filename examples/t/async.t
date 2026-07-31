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

my $t = Test::Nginx->new()->has(qw/http/)->plan(2)
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
    }
}

EOF

$t->write_file('index.html', '');
$t->run();

###############################################################################

like(http_get('/index.html'), qr/X-Async-Time:/, 'async handler');
unlike(http_get('/disabled'), qr/X-Async-Time:/, 'disabled async handler');

###############################################################################
