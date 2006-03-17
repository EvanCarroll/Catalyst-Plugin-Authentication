#!/usr/bin/perl

package Catalyst::Plugin::Authentication::User;

use strict;
use warnings;

sub id { die "virtual" }

sub store { die "virtual" }

sub supports {
    my ( $self, @spec ) = @_;

    my $cursor = $self->supported_features;

    # traverse the feature list,
    for (@spec) {
        #die "bad feature spec: @spec" if ref($cursor) ne "HASH";
        return if ref($cursor) ne "HASH";

        $cursor = $cursor->{$_};
    }

    return $cursor;
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::User - Base class for user objects.

=head1 SYNOPSIS

	package MyStore::User;
	use base qw/Catalyst::Plugin::Authentication::User/;

=head1 DESCRIPTION

This is the base class for authenticated 

=head1 METHODS

=over 4

=item id

A unique ID by which a user can be retrieved from the store.

=item store

Should return a class name that can be used to refetch the user using it's
ID.

=item supports

An introspection method used to determine what features a user object has, to support credential and authorization plugins.

=item 

=back

=cut


