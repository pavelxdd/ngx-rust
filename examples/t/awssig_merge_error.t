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
	->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:8080;

        location / {
            awssigv4 on;
        }
    }
}

EOF

eval { $t->run(); };

like($@, qr/Can't start nginx/, 'invalid configuration rejected');
like($t->read_file('error.log'),
	qr/failed to merge location configuration: awssigv4_access_key is required when awssigv4 is enabled/,
	'merge error logged');

###############################################################################
