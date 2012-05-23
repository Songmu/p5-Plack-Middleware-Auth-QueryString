package Plack::Middleware::Auth::QueryString;
use strict;
use warnings;
our $VERSION = '0.01';

use parent qw/Plack::Middleware/;

use Plack::Util::Accessor qw/key password/;
use Plack::Request;

sub prepare_app {
    my $self = shift;

    $self->key('key') unless $self->key;
    die 'requires password' unless $self->password;
}

sub call {
    my ($self, $env) = @_;

    return $self->validate($env) ? $self->app->($env) : $self->unauthorized;
}

sub validate {
    my ($self, $env) = @_;

    my $req = Plack::Request->new($env);
    $req->query_parameters->get($self->key) eq $self->password;
}

sub unauthorized {
    my $self = shift;

    my $body = 'Authorization required';
    return [
        401,
        [
            'Content-Type'    => 'text/plain',
            'Content-Lentgth' => length $body,
        ],
        [$body],
    ];
}

1;
__END__

=head1 NAME

Plack::Middleware::Auth::QueryString -

=head1 SYNOPSIS

  use Plack::Middleware::Auth::QueryString;

=head1 DESCRIPTION

Plack::Middleware::Auth::QueryString is

=head1 AUTHOR

Masayuki Matsuki E<lt>y.songmu@gmail.comE<gt>

=head1 SEE ALSO

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
