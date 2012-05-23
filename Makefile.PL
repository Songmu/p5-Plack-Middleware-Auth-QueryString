use inc::Module::Install;
name 'Plack-Middleware-Auth-QueryString';
all_from 'lib/Plack/Middleware/Auth/QueryString.pm';

# requires '';

tests 't/*.t';
author_tests 'xt';

test_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
