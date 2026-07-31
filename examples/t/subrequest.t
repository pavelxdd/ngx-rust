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

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(4)
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
            subrequest /backend;
        }

        location /missing {
            subrequest /not-found;
        }

        location /empty {
            subrequest /empty-backend;
        }

        location = /backend {
            internal;

            if ($arg_probe != 1) {
                return 400;
            }

            if ($http_x_subrequest != 1) {
                return 400;
            }

            return 200 "Hello from backend";
        }

        location = /empty-backend {
            internal;
            return 200;
        }
    }
}

EOF

$t->run();

###############################################################################

like(http_get('/'), qr/200 OK.*Hello from backend/s,
	'buffered subrequest response');
like(post('/'), qr/200 OK.*Hello from backend/s,
	'parent request body is isolated');
like(http_get('/missing'), qr/404 Not Found/s,
	'missing subrequest response');
like(http_get('/empty'), qr/200 OK/s,
	'empty subrequest response');

###############################################################################

sub post {
	my ($uri) = @_;
	return http(<<EOF);
POST $uri HTTP/1.1
Host: localhost
Content-Length: 5
Connection: close

hello
EOF
}

###############################################################################
