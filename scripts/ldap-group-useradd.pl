#!/usr/bin/perl

#
# (c) Security Guy 2015.01.21
#

use strict;
use warnings;

use POSIX qw(strftime);
use File::Basename;
use Getopt::Long;
use Net::LDAPS;
use Term::ReadKey;
use Sys::Hostname;

BEGIN {
    use constant VERSION    => "0.1";
}

my %settings = (
       'binddn' ,      'cn=hsecurity,dc=domain,dc=com',
       'ldap_port',    '636',
       'ldap_version', '3',
       'ldap_debug',   '0',
       'ldap_timeout', '30'
);

sub get_password {
        print "Enter " . $settings{'binddn'} . "'s password: ";
        ReadMode('noecho');
        my $pass = ReadLine(0);
        chomp $pass;
        ReadMode(0);
        print "\n\n";
        return ($pass);
}


my %dirs = (
        "ldap" => "/localservices/accounts/accounts/ldap",
        "logs" => "/localservices/accounts/accounts/logs"
);


sub display_help {
         print "
usage: $0  -g|--group=adminservers  -t|--tree=Domain  -u|--user=abcd  [-w|--vmware]  [-l|--listoptions]  [-h|--help] [-v|--version]

       $0  -g adminservers -t Domain -u abcd\n\n";
       exit 0;
}

sub rmkdir{
  my($tpath) = @_;
  my($accum);

  foreach my $mydir (split(/\//, $tpath)){
    $accum = "$accum" . "$mydir/";
    if($mydir ne ""){
      if(! -d "$accum"){
        print "[$0]: mkdir $accum\n";
        mkdir $accum;
        chmod(0700, $accum)
      }
    }
  }
}

sub iniRead
{
        my $ini = $_[0];
        my $conf;
        my $section;
        open (INI, "$ini") || die "Can't open $ini: $!\n";
        while (<INI>) {
                chomp;
                if (/^\s*\[\s*(.+?)\s*\]\s*$/) {
                        $section = $1;
                }

                if ( /^\s*([^=]+?)\s*=\s*(.*?)\s*$/ ) {
                        $conf->{$section}->{$1} = $2;

                        if (not defined $section) {
                                warn "Line outside of section '$_'\n";
                                next;
                        }

                }
        }
        close (INI);
        return $conf;
}
sub list;

# exiting cleanly from an LDAP connection
$SIG{__DIE__} = 'cleanup';

my $configfile = "/etc/ldapHostopia.conf";
my $inifile    = iniRead($configfile);
(my $logfile   = $dirs{"logs"} . "/" . basename($0)) =~ s/^(.*?)(?:\..*)?$/$1.log/;

my(%results) = ();

#Determine arguments
GetOptions( \ my %options,
        'g|group=s'        => \ my $group,
        'u|user=s'         => \ my $user,
        't|tree=s'         => \ my $tree,
        'l|listoptions'    => \ my $listoptions,
        'h|help'           => \&display_help,
        'w|vmware'         => \ my $vmware,
        'v|version'        => sub{ print "This is $0, version " .VERSION. "\n"; exit; }
) or &display_help;
if (defined ($listoptions)) { &list;&display_help;}
if ( (scalar(@ARGV < 0)) || (!defined($group)) || (!defined($tree)) || (!defined($user)) ) {  &display_help; }
if ( (!defined($inifile->{$tree})) || (!defined($inifile->{$tree}->{'base'})) )  { die "[$0]: ERROR: Unknown [ tree || base ] in $configfile"; }


###################
#  Sanity checks  #
###################
if ($group !~ /[a-zA-Z][a-zA-Z0-9]{2,40}/) {
        print "[*] $0: ERROR: group [$group] not string or length not in range(2,40)\n";
        exit 1;
}

if ($user !~ /[a-zA-Z][a-zA-Z0-9]{2,40}/) {
        print "[*] $0: ERROR: group [$user] not string or length not in range(2,40)\n";
        exit 1;
}

while( my( $name, $folder ) = each %dirs ) {
        rmkdir($folder) if (! -d $folder);;
}
# log cli options
&logit ( $logfile, "----------------------------" );

################
#  LDAP stuff  #
################
my $password = &get_password();

my $handle = Net::LDAPS->new(
         hostname,
         verify  => "none",
         onerror => 'warn',
         port    => $settings{'ldap_port'},
         version => $settings{'ldap_version'},
         debug   => $settings{'ldap_debug'},
         timeout => $settings{'ldap_timeout'},
) or die "Can not connect ldap: $@";

my $result = $handle->bind($settings{'binddn'}, password => $password);
die $result->error() if $result->code();


my %opt = ();
$opt{'base'}         = "o=" . $inifile->{$tree}->{'base'};

$opt{'groupbase'}    = "ou=groups," . $opt{'base'};
$opt{'groupbasedn'}  = "cn=$group,ou=groups," . $opt{'base'};

$opt{'userbase'}     = "ou=users," . $opt{'base'};
$opt{'userbasedn'}   = "uid=$user,ou=users," . $opt{'base'};

&logit ( $logfile, "$0 -g $group -u $user -t $tree" );

# make sure group name exist
if ( ! group_exists($handle, $group, $opt{'groupbase'}) ) {
        print ( "ERROR: group_exists() group => [" . $opt{'groupbasedn'} . "] does NOT exist!\n");
        &logit ( $logfile, "ERROR: group_exists() group => [" . $opt{'groupbasedn'} . "] does NOT exist!");
        &cleanup;
        exit 1;
}

# make sure user name exist
if ( ! user_exists ($handle, $user, $opt{'userbase'}) ) {
        print  ( "ERROR: user_exists() user => [" . $opt{'userbasedn'} . "] does NOT exist!\n");
        &logit ( $logfile, "ERROR: user_exists() user => [" . $opt{'userbasedn'} . "] does NOT exist!");
        &cleanup;
        exit 1;
}

if ( ! group_has_user ( $handle, $group, $opt{'groupbasedn'}, $user, $opt{'userbasedn'}) ) {
        &logit ( $logfile, "INFO: group_has_user() user [$user] not found in group [" . $opt{'groupbasedn'} ."]");
        if ( ! group_add_user ($handle, $group, $opt{'groupbasedn'}, $user, $opt{'userbasedn'} ) )
        {
                &logit($logfile, "SUCCESS: group_add_user() group => $group ".$opt{'groupbasedn'} . ", user => " . $opt{'userbasedn'} );
        } else {
                print ("ERROR: group $group ".$opt{'groupbasedn'}.", user => " . $opt{'userbasedn'} . "\n");
                &logit($logfile,"ERROR: group_add_user() group $group ".$opt{'groupbasedn'}.", user => " . $opt{'userbasedn'} );
                &cleanup;
                exit 1;
        }
}

if ( ! user_has_description ($handle, $user,  $opt{'userbasedn'}, $opt{'groupbasedn'} ) ) {
        &logit ( $logfile, "INFO: user_has_description() description=" . $opt{'groupbasedn'} . " missing from user " . $opt{'userbasedn'} );
} else {
        &logit ( $logfile, "INFO: user_has_description() description=" . $opt{'groupbasedn'} . " exists for user " . $opt{'userbasedn'} );
        &cleanup;
        exit 1;
}

if ( user_add_description ($handle, $user, $opt{'userbasedn'}, $opt{'groupbasedn'} ) )
{
#        &logit ( $logfile, "SUCCESS: userdn => ".$opt{'userbasedn'} . ", description =>  " . $opt{'groupbasedn'} );
#} else {
        print ( "ERROR: user_add_description() userdn => ".$opt{'userbasedn'}.", description => " . $opt{'groupbasedn'} . "\n" );
        &cleanup;
        exit 1;
}

print "SUCCESS: tail $logfile\n";

# close connection to ldap
&cleanup;
exit(0);


####################
#  LDAP FUNCTIONS  #
####################

## Check whether or not the group exists
sub group_exists {
        my ( $ldap, $name, $where ) = @_;
        my ( $msg );

        $msg = $ldap->search ( base => $where,
                               filter => "(&(objectclass=top)(|(objectclass=groupOfUniqueNames)(objectclass=posixGroup))(cn=$name))"
                             );
        $msg->code && die $msg->error;

        &logit ($logfile, "SUCCESS: group_exists() Checked for existing group cn=$name,$where");

        return ($msg->count);
}

## Check whether or not the user exists
sub user_has_description {
        my ( $ldap, $user, $userdn, $groupdn ) = @_;
        my ( $msg );

        $msg = $ldap->search ( base   => $userdn,
                               scope  => "base",
                               filter => "(&(uid=$user)(description=$groupdn))"
                             );
        $msg->code && die $msg->error;

        &logit ($logfile, "SUCCESS: user_has_description() Checked for existing description=$groupdn in => $userdn");

        return ($msg->count);
}

## Check whether or not the user exists
sub user_exists {
        my ( $ldap, $name, $where ) = @_;
        my ( $msg );

        $msg = $ldap->search ( base   => $where,
                               scope  => "one",
                               filter => "(&(objectclass=top)(objectclass=posixAccount)(objectclass=inetOrgPerson)(objectclass=hSecurity)(uid=$name))"
                             );
        $msg->code && die $msg->error;

        &logit ($logfile, "SUCCESS: user_exists() Checked for existing user => uid=$name,$where");

        return ($msg->count);
}

## Check whether or not the user is part of group
sub group_has_user {
        my ( $ldap, $grp, $grpbase, $myuser ) = @_;
        my ( $msg );

        my $filter = '';

        if (!defined ($vmware)) {
                # regular posix
                $filter = sprintf ("(&(objectclass=top)(objectclass=posixGroup)(memberUid=%s)(hMemberDN=%s))",$myuser,$opt{'userbasedn'} );
        } else {
                # vmware groupOfUniqueNames
                $filter = sprintf ("(&(objectclass=top)(objectclass=groupOfUniqueNames)(uniqueMember=%s))",$opt{'userbasedn'} );
        }

        $msg = $ldap->search ( base => $grpbase,
                               filter => $filter
                             );
        $msg->code && die $msg->error;

        &logit ($logfile, "SUCCESS: group_has_user() Checked for filter $filter => group $grpbase");

        return ($msg->count);
}


## Add new group
sub group_add_user {
        my ( $ldap, $grp, $grpbasedn, $user, $userdn) = @_;
        my ( $msg );

        if(!defined($vmware)) {

                $msg = $ldap->modify($grpbasedn, add => { memberUid => "$user", hMemberDN => "$userdn" } );
        } else {
                $msg = $ldap->modify($grpbasedn, add => { uniqueMember => "$userdn" } );
        }

        if ($msg->code) {
                if(!defined($vmware)) {
                        print ("ERROR: group_add_user() group => $grpbasedn, user => $user, hMemberDN => $userdn, memberUid => $user reason: $msg->error");
                        &logit ($logfile, "ERROR: group_add_user() group => $grpbasedn, user => $user, hMemberDN => $userdn, memberUid => $user reason: $msg->error");
                } else {
                        print ("ERROR: group_add_user() group => $grpbasedn, user => $user, uniqueMember => $userdn reason: $msg->error");
                        &logit ($logfile, "ERROR: group_add_user() group => $grpbasedn, user => $user, uniqueMember => $userdn reason: $msg->error");
                }

                return 1;

        } else {
                if(!defined($vmware)) {
                        &logit ($logfile, "SUCCESS: group_add_user() group => $grpbasedn, user => $user, hMemberDN => $userdn");
                } else {
                        &logit ($logfile, "SUCCESS: group_add_user() group => $grpbasedn, user => $user, uniqueMember => $userdn");
                }

                return 0;
        }

}

## Set hStatus=5 to the user
sub user_add_description {
        my ( $ldap, $user, $userdn, $newentry) = @_;
        my ( $msg );

        #print "DEBUG: user_add_description() user: $user, userdn: $userdn, newentry: $newentry\n";

        $msg = $ldap->modify($userdn, add => { description => "$newentry" } );

        if ($msg->code) {
                print ("ERROR: user => $user, DN => $userdn, description => $newentry reason: $msg->error");
                &logit ($logfile, "ERROR: user => $user, DN => $userdn, description => $newentry reason: $msg->error");
                return 1;
        } else {
                &logit ($logfile, "SUCCESS: user => $user, DN => $userdn, description => $newentry SUCCESS");
                return 0;
        }

}


sub cleanup {
        if ($handle) {
                $handle->unbind;
                $handle->disconnect;
        }
        &logit ($logfile, "");
}

sub logit
{

        my ($LogFile,$Msg) = @_;

        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);

        $year += 1900; 
        $mon  = sprintf("%02d", $mon+1);
        $mday = sprintf("%02d", $mday);
        $hour = sprintf("%02d", $hour);
        $min  = sprintf("%02d", $min);
        $sec  = sprintf("%02d", $sec);

        my ($datestamp) = $year ."-" . $mon ."-" . $mday ." " . $hour . ":" . $min .":" . $sec;
        open(FILEH, ">>$LogFile") ||return();
        print FILEH "$datestamp | $Msg\n";
        close(FILEH);

        return 1;
}

sub list {
        print "\n";

        print "TREES: ";
        while( my( $key, $val ) = each %{$inifile} ) {
                print $key . " ";
        }
        print "\n";

}
