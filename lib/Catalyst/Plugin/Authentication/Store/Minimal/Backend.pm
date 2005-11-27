#!/usr/bin/perl

package Catalyst::Plugin::Authentication::Store::Minimal::Backend;

use strict;
use warnings;

use Catalyst::Plugin::Authentication::User::Hash;
use Scalar::Util ();

sub new {
    my ( $class, $hash ) = @_;

    bless { hash => $hash }, $class;
}

sub from_session {
	my ( $self, $c, $id ) = @_;

	return $id if ref $id;

	$self->get_user( $id );
}

sub get_user {
    my ( $self, $id ) = @_;

    return unless exists $self->{hash}{$id};

    my $user = $self->{hash}{$id};

    if ( ref $user ) {
        if ( Scalar::Util::blessed($user) ) {
			$user->store( $self );
			$user->id( $id );
            return $user;
        }
        elsif ( ref $user eq "HASH" ) {
            return bless $user, "Catalyst::Plugin::Authentication::User::Hash";
        }
        else {
            Catalyst::Exception->throw( "The user '$id' is a reference of type "
                  . ref($user)
                  . " but should be a HASH" );
        }
    }
    else {
        Catalyst::Exception->throw(
            "The user '$id' is has to be a hash reference or an object");
    }

    return $user;
}

sub user_supports {
    my $self = shift;

    # choose a random user
    scalar keys %{ $self->{hash} };
    ( undef, my $user ) = each %{ $self->{hash} };

    $user->supports(@_);
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::Store::Minimal::Backend - Minimal
authentication storage backend.

=head1 SYNOPSIS

    # you probably just want Store::Minimal under most cases,
    # but if you insist you can instantiate your own store:

    use Catalyst::Plugin::Authentication::Store::Minimal::Backend;

    use Catalyst qw/
        Authentication
        Authentication::Credential::Password
    /;

    my %users = (
        user => { password => "s3cr3t" },
    );
    
    our $users = Catalyst::Plugin::Authentication::Store::Minimal::Backend->new(\%users);

    sub action : Local {
        my ( $self, $c ) = @_;

        $c->login( $users->get_user( $c->req->param("login") ),
            $c->req->param("password") );
    }

=head1 DESCRIPTION

You probably want L<Catalyst::Plugin::Authentication::Store::Minimal>, unless
you are mixing several stores in a single app and one of them is Minimal.

Otherwise, this lets you create a store manually.

=head1 METHODS

=over 4

=item new $hash_ref

Constructs a new store object, which uses the supplied hash ref as it's backing
structure.

=item get_user $id

Keys the hash by $id and returns the value.

If the return value is unblessed it will be blessed as
L<Catalyst::Plugin::Authentication::User::Hash>.

=item from_session $id

Delegates to C<get_user>.

=item user_supports

Chooses a random user from the hash and delegates to it.

=back

=cut


