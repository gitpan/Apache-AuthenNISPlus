package Apache::AuthenNISPlus;

use strict;
use Apache::Constants qw/:common/;
use vars qw/%ENV/;

$Apache::AuthenNISPlus::VERSION = '0.03';
my $self="Apache::AuthenNISPlus";

sub handler {

  # get request object
  my $r = shift;

  # service only the first internal request
  return OK unless $r->is_initial_req;

  # get password user entered in browser
  my($res, $sent_pwd) = $r->get_basic_auth_pw;

  # decline if not basic
  return $res if $res;

  # get user name
  my $name = $r->connection->user;

  # be sure username is reasonable
  $name=~m/(\w+)/; $name=$1;

  # blank user name would cause problems
  unless($name){
    $r->note_basic_auth_failure;
    $r->log_reason("$self: no username supplied", $r->uri);
    return AUTH_REQUIRED;
  }

  # load apache config vars
  my $dir_config = $r->dir_config;   

  # get passwd table name
  my $passwd_table = $dir_config->get("NISPlus_Passwd_Table");

  # taint allowance
  $ENV{PATH}="/bin";

  # if this module is to be exposed to an unruly user base, it would
  # be safer to gather the nismatch output via an underprivileged child
  # instead of letting the shell get involved

  # construct nismatch command
  my $command = "/usr/bin/nismatch $name $passwd_table";

  # get passwd entry
  my $out = `$command`;
  if($?){
    $r->note_basic_auth_failure;
    $r->log_reason(
      "$self: user $name is not in $passwd_table", $r->uri
    );
    return AUTH_REQUIRED;
  }

  # get password, group from password entry
  my($pwd, $group) = (split ":", $out)[1,3];

  #stash group id lookup for authorization check 
  $r->notes($name."Group", $group);
  unless(crypt($sent_pwd, $pwd) eq $pwd) {
    $r->note_basic_auth_failure;
    $r->log_reason(
      "$self: user $name password does not match $passwd_table", $r->uri
    );
    return AUTH_REQUIRED;
  }
  $r->push_handlers(PerlAuthzHandler => \&authz);
  return OK;
}

sub authz {
 
 # get request object
  my $r = shift;
  my $requires = $r->requires;
  return OK unless $requires;

  # get user name
  my $name = $r->connection->user;

  # get group table name
  my $dir_config = $r->dir_config;   
  my $group_table=$dir_config->get("NISPlus_Group_Table");

  # construct nismatch command
  my $command = "/usr/bin/nismatch $name $group_table";

  for my $req (@$requires) {
    my($require, @rest) = split /\s+/, $req->{requirement};

    #ok if user is simply authenticated
    if($require eq "valid-user"){return OK}

    # ok if user is one of these users
    elsif($require eq "user") {return OK if grep $name eq $_, @rest}

    # ok if user is member of a required group.
    elsif($require eq "group") {
      for my $group (@rest) {
        my $out = `$command`;
        next if $?;
        my($gname, $gid) = (split ":", $out)[0,2];
        return OK if $r->notes($name."Group") == $gid;
      }
    }
  }
  $r->note_basic_auth_failure;
  $r->log_reason(
    "$self: user $name not member of required group in $group_table", $r->uri
  );
  return AUTH_REQUIRED;
}

1;

__END__

=pod

=head1 NAME

Apache::AuthenNISPlus - Authenticate into a NIS+ domain

=head1 SYNOPSIS

 #httpd.conf
 <Location>
   AuthName "your nis+ account"
   AuthType Basic
   PerlSetVar NISPlus_Passwd_Table passwd.org_dir.yoyodyne.com
   PerlSetVar NISPlus_Group_Table group.org_dir.yoyodyne.com
   PerlAuthenHandler Apache::AuthenNISPlus
   require group eng
   require user john larry
 </Location>

=head1 DESCRIPTION

Authenticate into a nis+ domain.

This is pretty lame in that it simply executes "/usr/bin/nismatch"
with the appropriate arguments.  If exposed to an unruly user base,
that part should be rewritten to gather output from an
underprivileged child instead of letting the shell get involved.  An
even better answer would probably be to hook into Net::NISPlus, but I
could not figure out how to do that in the few hours I had available.

=head1 AUTHOR

valerie at savina dot com (Valerie Delane), based more or less on
code shamelessly lifted from Doug MacEachern's Apache::AuthNIS.

=head1 COPYRIGHT

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

mod_perl(3), Apache(3), nismatch(1)

=cut
