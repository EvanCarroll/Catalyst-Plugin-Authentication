#!/usr/bin/perl

package Catalyst::Plugin::Authentication;

use base qw/Class::Accessor::Fast Class::Data::Inheritable/;

BEGIN {
    __PACKAGE__->mk_accessors(qw/_user/);
    __PACKAGE__->mk_classdata($_) for qw/_auth_stores _auth_store_names/;
}

use strict;
use warnings;

use Tie::RefHash;
use Class::Inspector;

# this optimization breaks under Template::Toolkit
# use user_exists instead
#BEGIN {
#	require constant;
#	constant->import(have_want => eval { require Want });
#}

our $VERSION = "0.08";

sub set_authenticated {
    my ( $c, $user ) = @_;

    $c->user($user);
    $c->request->{user} = $user;    # compatibility kludge

    if (    $c->isa("Catalyst::Plugin::Session")
        and $c->config->{authentication}{use_session}
        and $user->supports("session") )
    {
        $c->save_user_in_session($user);
    }

    $c->NEXT::set_authenticated($user);
}

sub user {
    my $c = shift;

    if (@_) {
        return $c->_user(@_);
    }

    if ( defined(my $user = $c->_user) ) {
        return $user;
    } else {
        my $frozen = $c->_user_in_session;
        return $c->auth_restore_user($frozen);
    }
}

sub user_exists {
	my $c = shift;
	return defined($c->_user) || defined($c->_user_in_session);
}

sub _user_in_session {
    my $c = shift;

    if ( $c->isa("Catalyst::Plugin::Session") and $c->session_is_valid ) {
        return $c->session->{__user};
    }

    return;
}

sub save_user_in_session {
    my ( $c, $user ) = @_;

    my $store = $user->store || ref $user;
    $c->session->{__user_store} = $c->get_auth_store_name($store) || $store;
    $c->session->{__user} = $user->for_session;
}

sub logout {
    my $c = shift;

    $c->user(undef);

    if (    $c->isa("Catalyst::Plugin::Session")
        and $c->config->{authentication}{use_session} )
    {
        delete @{ $c->session }{qw/__user __user_store/};
    }
    
    $c->NEXT::logout(@_);
}

sub get_user {
    my ( $c, $uid, @rest ) = @_;

    if ( my $store = $c->default_auth_store ) {
        return $store->get_user( $uid, @rest );
    }
    else {
        Catalyst::Exception->throw(
                "The user id $uid was passed to an authentication "
              . "plugin, but no default store was specified" );
    }
}

sub auth_restore_user {
    my ( $c, $frozen_user, $store_name ) = @_;

    return
      unless $c->isa("Catalyst::Plugin::Session")
      and $c->config->{authentication}{use_session}
      and $c->sessionid;

    $store_name  ||= $c->session->{__user_store};
    $frozen_user ||= $c->session->{__user};

    my $store = $c->get_auth_store($store_name);
    $c->_user( my $user = $store->from_session( $c, $frozen_user ) );

    return $user;

}

sub setup {
    my $c = shift;

    my $cfg = $c->config->{authentication} || {};

    %$cfg = (
        use_session => 1,
        %$cfg,
    );

    $c->register_auth_stores(
        default => $cfg->{store},
        %{ $cfg->{stores} || {} },
    );

    $c->NEXT::setup(@_);
}

sub get_auth_store {
    my ( $self, $name ) = @_;
    $self->auth_stores->{$name} || ( Class::Inspector->loaded($name) && $name );
}

sub get_auth_store_name {
    my ( $self, $store ) = @_;
    $self->auth_store_names->{$store};
}

sub register_auth_stores {
    my ( $self, %new ) = @_;

    foreach my $name ( keys %new ) {
        my $store = $new{$name} or next;
        $self->auth_stores->{$name}       = $store;
        $self->auth_store_names->{$store} = $name;
    }
}

sub auth_stores {
    my $self = shift;
    $self->_auth_stores(@_) || $self->_auth_stores( {} );
}

sub auth_store_names {
    my $self = shift;

    $self->_auth_store_names || do {
        tie my %hash, 'Tie::RefHash';
        $self->_auth_store_names( \%hash );
      }
}

sub default_auth_store {
    my $self = shift;

    if ( my $new = shift ) {
        $self->register_auth_stores( default => $new );
    }

    $self->get_auth_store("default");
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authentication - Infrastructure plugin for the Catalyst
authentication framework.

=head1 SYNOPSIS

    use Catalyst qw/
        Authentication
        Authentication::Store::Foo
        Authentication::Credential::Password
    /;

    # later on ...
    # ->login is provided by the Credential::Password module
    $c->login('myusername', 'mypassword');
    my $age = $c->user->age;
    $c->logout;

=head1 DESCRIPTION

The authentication plugin provides generic user support. It is the basis 
for both authentication (checking the user is who they claim to be), and 
authorization (allowing the user to do what the system authorises them to do).

Using authentication is split into two parts. A Store is used to actually 
store the user information, and can store any amount of data related to 
the user. Multiple stores can be accessed from within one application. 
Credentials are used to verify users, using the store, given data from 
the frontend.

To implement authentication in a Catalyst application you need to add this 
module, plus at least one store and one credential module.

Authentication data can also be stored in a session, if the application 
is using the L<Catalyst::Plugin::Session> module.

=head1 INTRODUCTION

=head2 The Authentication/Authorization Process

Web applications typically need to identify a user - to tell the user apart
from other users. This is usually done in order to display private information
that is only that user's business, or to limit access to the application so
that only certain entities can access certain parts.

This process is split up into several steps. First you ask the user to identify
themselves. At this point you can't be sure that the user is really who they
claim to be.

Then the user tells you who they are, and backs this claim with some piece of
information that only the real user could give you. For example, a password is
a secret that is known to both the user and you. When the user tells you this
password you can assume they're in on the secret and can be trusted (ignore
identity theft for now). Checking the password, or any other proof is called
B<credential verification>.

By this time you know exactly who the user is - the user's identity is
B<authenticated>. This is where this module's job stops, and other plugins step
in. The next logical step is B<authorization>, the process of deciding what a
user is (or isn't) allowed to do. For example, say your users are split into
two main groups - regular users and administrators. You should verify that the
currently logged in user is indeed an administrator before performing the
actions of an administrative part of your application. One way to do this is
with role based access control.

=head2 The Components In This Framework

=head3 Credential Verifiers

When user input is transferred to the L<Catalyst> application (typically via
form inputs) this data then enters the authentication framework through these
plugins.

These plugins check the data, and ensure that it really proves the user is who
they claim to be.

=head3 Storage Backends

The credentials also identify a user, and this family of modules is supposed to
take this identification data and return a standardized object oriented
representation of users.

When a user is retrieved from a store it is not necessarily authenticated.
Credential verifiers can either accept a user object, or fetch the object
themselves from the default store.

=head3 The Core Plugin

This plugin on its own is the glue, providing store registration, session
integration, and other goodness for the other plugins.

=head3 Other Plugins

More layers of plugins can be stacked on top of the authentication code. For
example, L<Catalyst::Plugin::Session::PerUser> provides an abstraction of
browser sessions that is more persistent per users.
L<Catalyst::Plugin::Authorization::Roles> provides an accepted way to separate
and group users into categories, and then check which categories the current
user belongs to.

=head1 EXAMPLE

Let's say we were storing users in an Apache style htpasswd file. Users are
stored in that file, with a hashed password and some extra comments. Users are
verified by supplying a password which is matched with the file.

This means that our application will begin like this:

    package MyApp;

    use Catalyst qw/
        Authentication
        Authentication::Credential::Password
        Authentication::Store::Htpasswd
    /;

    __PACKAGE__->config->{authentication}{htpasswd} = "passwdfile";

This loads the appropriate methods and also sets the htpasswd store as the
default store.
    
So, now that we have the code loaded we need to get data from the user into the
credential verifier.

Let's create an authentication controller:

    package MyApp::Controller::Auth;

    sub login : Local {
        my ( $self, $c ) = @_;

        if (    my $user = $c->req->param("user")
            and my $password = $c->req->param("password") )
        {
            if ( $c->login( $user, $password ) ) {
                $c->res->body( "hello " . $c->user->name );
            } else {
                # login incorrect
            }
        }
        else {
            # invalid form input
        }
    }

This code should be very readable. If all the necessary fields are supplied,
call the L<Authentication::Credential::Password/login> method on the
controller. If that succeeds the user is logged in.

It could be simplified though:

    sub login : Local {
        my ( $self, $c ) = @_;

        if ( $c->login ) {
            ...
        }
    }

Since the C<login> method knows how to find logically named parameters on its
own.

The credential verifier will ask the default store to get the user whose ID is
the user parameter. In this case the default store is the htpasswd one. Once it
fetches the user from the store the password is checked and if it's OK
C<< $c->user >> will contain the user object returned from the htpasswd store.

We can also pass a user object to the credential verifier manually, if we have
several stores per app. This is discussed in
L<Catalyst::Plugin::Authentication::Store>.

Now imagine each admin user has a comment set in the htpasswd file saying
"admin".

A restricted action might look like this:

    sub restricted : Local {
        my ( $self, $c ) = @_;

        $c->detach("unauthorized")
          unless $c->user_exists
          and $c->user->extra_info() eq "admin";

        # do something restricted here
    }

This is somewhat similar to role based access control.
L<Catalyst::Plugin::Authentication::Store::Htpasswd> treats the extra info
field as a comma separated list of roles if it's treated that way. Let's
leverage this. Add the role authorization plugin:

    use Catalyst qw/
        ...
        Authorization::Roles
    /;

    sub restricted : Local {
        my ( $self, $c ) = @_;

        $c->detach("unauthorized") unless $c->check_roles("admin");

        # do something restricted here
    }

This is somewhat simpler and will work if you change your store, too, since the
role interface is consistent.

Let's say your app grew, and you now have 10000 users. It's no longer efficient
to maintain an htpasswd file, so you move this data to a database.

    use Catalyst qw/
        Authentication
        Authentication::Credential::Password
        Authentication::Store::DBIC
        Authorization::Roles
    /;

    __PACKAGE__->config->{authentication}{dbic} = ...; # see the DBIC store docs

The rest of your code should be unchanged. Now let's say you are integrating
typekey authentication to your system. For simplicity's sake we'll assume that
the user's are still keyed in the same way.

    use Catalyst qw/
        Authentication
        Authentication::Credential::Password
        Authentication::Credential::TypeKey
        Authentication::Store::DBIC
        Authorization::Roles
    /;

And in your auth controller add a new action:

    sub typekey : Local {
        my ( $self, $c ) = @_;

        if ( $c->authenticate_typekey) { # uses $c->req and Authen::TypeKey
            # same stuff as the $c->login method
            # ...
        }
    }

You've now added a new credential verification mechanizm orthogonally to the
other components. All you have to do is make sure that the credential verifiers
pass on the same types of parameters to the store in order to retrieve user
objects.

=head1 METHODS

=over 4 

=item user

Returns the currently logged in user or undef if there is none.

=item user_exists

Whether or not a user is logged in right now.

The reason this method exists is that C<< $c->user >> may needlessly load the
user from the auth store.

If you're just going to say

	if ( $c->user_exists ) {
		# foo
	} else {
		$c->forward("login");
	}

it should be more efficient than C<< $c->user >> when a user is marked in the
session but C<< $c->user >> hasn't been called yet.

=item logout

Delete the currently logged in user from C<user> and the session.

=item get_user $uid

Fetch a particular users details, defined by the given ID, via the default store.

=back

=head1 CONFIGURATION

=over 4

=item use_session

Whether or not to store the user's logged in state in the session, if the
application is also using the L<Catalyst::Plugin::Session> plugin. This 
value is set to true per default.

=item store

If multiple stores are being used, set the module you want as default here.

=item stores

If multiple stores are being used, you need to provide a name for each store
here, as a hash, the keys are the names you wish to use, and the values are
the the names of the plugins.

 # example
 __PACKAGE__->config( authentication => {
                        store => 'Catalyst::Plugin::Authentication::Store::HtPasswd',
                        stores => { 
                           'dbic' => 'Catalyst::Plugin::Authentication::Store::DBIC'
                                  }
                                         });

=back

=head1 METHODS FOR STORE MANAGEMENT

=over 4

=item default_auth_store

Return the store whose name is 'default'.

This is set to C<< $c->config->{authentication}{store} >> if that value exists,
or by using a Store plugin:

	use Catalyst qw/Authentication Authentication::Store::Minimal/;

Sets the default store to
L<Catalyst::Plugin::Authentication::Store::Minimal::Backend>.


=item get_auth_store $name

Return the store whose name is $name.

=item get_auth_store_name $store

Return the name of the store $store.

=item auth_stores

A hash keyed by name, with the stores registered in the app.

=item auth_store_names

A ref-hash keyed by store, which contains the names of the stores.

=item register_auth_stores %stores_by_name

Register stores into the application.

=back

=head1 INTERNAL METHODS

=over 4

=item set_authenticated $user

Marks a user as authenticated. Should be called from a
C<Catalyst::Plugin::Authentication::Credential> plugin after successful
authentication.

This involves setting C<user> and the internal data in C<session> if
L<Catalyst::Plugin::Session> is loaded.

=item auth_restore_user $user

Used to restore a user from the session, by C<user> only when it's actually
needed.

=item save_user_in_session $user

Used to save the user in a session.

=item prepare

Revives a user from the session object if there is one.

=item setup

Sets the default configuration parameters.

=item 

=back

=head1 SEE ALSO

This list might not be up to date.

=head2 User Storage Backends

L<Catalyst::Plugin::Authentication::Store::Minimal>,
L<Catalyst::Plugin::Authentication::Store::Htpasswd>,
L<Catalyst::Plugin::Authentication::Store::DBIC> (also works with Class::DBI).

=head2 Credential verification

L<Catalyst::Plugin::Authentication::Credential::Password>,
L<Catalyst::Plugin::Authentication::Credential::HTTP>,
L<Catalyst::Plugin::Authentication::Credential::TypeKey>

=head2 Authorization

L<Catalyst::Plugin::Authorization::ACL>,
L<Catalyst::Plugin::Authorization::Roles>

=head2 Internals Documentation

L<Catalyst::Plugin::Authentication::Store>

=head2 Misc

L<Catalyst::Plugin::Session>,
L<Catalyst::Plugin::Session::PerUser>

=head1 DON'T SEE ALSO

This module along with its sub plugins deprecate a great number of other
modules. These include L<Catalyst::Plugin::Authentication::Simple>,
L<Catalyst::Plugin::Authentication::CDBI>.

At the time of writing these plugins have not yet been replaced or updated, but
should be eventually: L<Catalyst::Plugin::Authentication::OpenID>,
L<Catalyst::Plugin::Authentication::LDAP>,
L<Catalyst::Plugin::Authentication::CDBI::Basic>,
L<Catalyst::Plugin::Authentication::Basic::Remote>.

=head1 AUTHORS

Yuval Kogman, C<nothingmuch@woobling.org>

Jess Robinson

David Kamholz

=head1 COPYRIGHT & LICENSE

        Copyright (c) 2005 the aforementioned authors. All rights
        reserved. This program is free software; you can redistribute
        it and/or modify it under the same terms as Perl itself.

=cut

