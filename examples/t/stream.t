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
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_return/)->plan(2)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen        127.0.0.1:8080;
        stream_probe  on;
        return        $stream_probe;
    }

    server {
        listen        127.0.0.1:8081;
        stream_probe  off;
        return        $stream_probe;
    }
}

EOF

$t->run();

###############################################################################

is(stream('127.0.0.1:' . port(8080))->read(), 'seen', 'preread context');
is(stream('127.0.0.1:' . port(8081))->read(), 'not-seen', 'disabled server');

###############################################################################
