#!/usr/bin/perl

package Catalyst::Plugin::Authentication::Store::Minimal;

use strict;
use warnings;

use Catalyst::Plugin::Authentication::Store::Minimal::Backend;

sub setup {
    my $c = shift;

    $c->default_auth_store(
        Catalyst::Plugin::Authentication::Store::Minimal::Backend->new(
            $c->config->{authentication}{users}
        )
    );

	$c->NEXT::setup(@_);
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::Store::Minimal - Authentication
database in C<<$c->config>>.

=head1 SYNOPSIS

    use Catalyst qw/
      Authentication
      Authentication::Store::Minimal
      Authentication::Credential::Password
      /;

    __PACKAGE__->config->{authentication}{users} = {
        name => {
            password => "s3cr3t",
            roles    => [qw/admin editor/],
            ...
        },
    };

    sub login : Global {
        my ( $self, $c ) = @_;

        $c->login( $c->req->param("login"), $c->req->param("password"), );
    }

=head1 DESCRIPTION

This authentication store plugin lets you create a very quick and dirty user
database in your application's config hash.

It's purpose is mainly for testing, and it should probably be replaced by a
more "serious" store for production.

The hash in the config, as well as the user objects/hashes are freely mutable
at runtime.

=head1 METHODS

=over 4

=item setup

This method will popultate C<< $c->config->{authentication}{store} >> so that
L<Catalyst::Plugin::Authentication/default_auth_store> can use it.

=back

=cut


