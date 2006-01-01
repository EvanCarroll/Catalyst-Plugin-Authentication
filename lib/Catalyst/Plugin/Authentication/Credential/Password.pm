#!/usr/bin/perl

package Catalyst::Plugin::Authentication::Credential::Password;

use strict;
use warnings;

use Scalar::Util        ();
use Catalyst::Exception ();
use Digest              ();

sub login {
    my ( $c, $user, $password ) = @_;

    for ( $c->request ) {
        unless ( $user ||= $_->param("login")
            || $_->param("user")
            || $_->param("username") )
        {
            $c->log->debug(
                "Can't login a user without a user object or user ID param");
            return;
        }

        unless ( $password ||= $_->param("password")
            || $_->param("passwd")
            || $_->param("pass") )
        {
            $c->log->debug("Can't login a user without a password");
            return;
        }
    }

    unless ( Scalar::Util::blessed($user)
        and $user->isa("Catalyst:::Plugin::Authentication::User") )
    {
        if ( my $user_obj = $c->get_user($user) ) {
            $user = $user_obj;
        }
        else {
            $c->log->debug("User '$user' doesn't exist in the default store")
              if $c->debug;
            return;
        }
    }

    if ( $c->_check_password( $user, $password ) ) {
        $c->set_authenticated($user);
        $c->log->debug("Successfully authenticated user '$user'.")
          if $c->debug;
        return 1;
    }
    else {
        $c->log->debug(
            "Failed to authenticate user '$user'. Reason: 'Incorrect password'"
          )
          if $c->debug;
        return;
    }
}

sub _check_password {
    my ( $c, $user, $password ) = @_;

    if ( $user->supports(qw/password clear/) ) {
        return $user->password eq $password;
    }
    elsif ( $user->supports(qw/password crypted/) ) {
        my $crypted = $user->crypted_password;
        return $crypted eq crypt( $password, $crypted );
    }
    elsif ( $user->supports(qw/password hashed/) ) {

        my $d = Digest->new( $user->hash_algorithm );
        $d->add( $user->password_pre_salt || '' );
        $d->add($password);
        $d->add( $user->password_post_salt || '' );

        my $stored   = $user->hashed_password;
        my $computed = $d->digest;

        return ( ( $computed eq $stored )
              || ( unpack( "H*", $computed ) eq $stored ) );
    }
    elsif ( $user->supports(qw/password salted_hash/) ) {
        require Crypt::SaltedHash;

        my $salt_len =
          $user->can("password_salt_len") ? $user->password_salt_len : 0;

        return Crypt::SaltedHash->validate( $user->hashed_password, $password,
            $salt_len );
    }
    elsif ( $user->supports(qw/password self_check/) ) {

        # while somewhat silly, this is to prevent code duplication
        return $user->check_password($password);

    }
    else {
        Catalyst::Exception->throw(
                "The user object $user does not support any "
              . "known password authentication mechanism." );
    }
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication::Credential::Password - Authenticate a user
with a password.

=head1 SYNOPSIS

    use Catalyst qw/
      Authentication
      Authentication::Store::Foo
      Authentication::Credential::Password
      /;

    package MyApp::Controller::Auth;

    # *** NOTE ***
    # if you place an action named 'login' in your application's root (as
    # opposed to inside a controller) the following snippet will recurse,
    # giving you lots of grief.
    # never name actions in the root controller after plugin methods - use
    # controllers and : Global instead.

    sub login : Local {
        my ( $self, $c ) = @_;

        $c->login( $c->req->param('username'), $c->req->param('password') );
    }

=head1 DESCRIPTION

This authentication credential checker takes a username (or userid) and a 
password, and tries various methods of comparing a password based on what 
the chosen store's user objects support:

=over 4

=item clear text password

If the user has clear a clear text password it will be compared directly.

=item crypted password

If UNIX crypt hashed passwords are supported, they will be compared using
perl's builtin C<crypt> function.

=item hashed password

If the user object supports hashed passwords, they will be used in conjunction
with L<Digest>.

=back

=head1 METHODS

=over 4

=item login $username, $password

Try to log a user in.

C<$username> can be a string (e.g. retrieved from a form) or an object. 
If the object is a L<Catalyst::Plugin::Authentication::User> it will be used 
as is. Otherwise C<< $c->get_user >> is used to retrieve it.

C<$password> is a string.

If C<$username> or C<$password> are not provided, the query parameters 
C<login>, C<user>, C<username> and C<password>, C<passwd>, C<pass> will 
be tried instead.

=back

=head1 RELATED USAGE

After the user is logged in, the user object for the current logged in user 
can be retrieved from the context using the C<< $c->user >> method.

The current user can be logged out again by calling the C<< $c->logout >> 
method.

=head1 SUPPORTING THIS PLUGIN

For a User class to support credential verification using this plugin, it
needs to indicate what sort of password a given user supports 
by implementing the C<supported_features> method in one or many of the 
following ways:

=head2 Clear Text Passwords

Predicate:

	$user->supported_features(qw/password clear/);

Expected methods:

=over 4

=item password

Returns the user's clear text password as a string to be compared with C<eq>.

=back

=head2 Crypted Passwords

Predicate:

	$user->supported_features(qw/password crypted/);

Expected methods:

=over 4

=item crypted_password

Return's the user's crypted password as a string, with the salt as the first two chars.

=back

=head2 Hashed Passwords

Predicate:

	$user->supported_features(qw/password hashed/);

Expected methods:

=over 4

=item hashed_password

Return's the hash of the user's password as B<binary>.

=item hash_algorithm

Returns a string suitable for feeding into L<Digest/new>.

=item password_pre_salt

=item password_post_salt

Returns a string to be hashed before/after the user's password. Typically only
a pre-salt is used.

=back

=head2 Crypt::SaltedHash Passwords

Predicate:

	$user->supported_features(qw/password salted_hash/);

Expected methods:

=over 4

=item hashed_password

Returns the hash of the user's password as returned from L<Crypt-SaltedHash>->generate.

=back

Optional methods:

=over 4

=item password_salt_len

Returns the length of salt used to generate the salted hash.

=back

=cut


