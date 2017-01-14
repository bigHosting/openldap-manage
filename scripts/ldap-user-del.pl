#!/usr/bin/perl

#
# (c) Security Guy 2015.01.30
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
usage: $0

           -t|--tree=Domain
           -u|--user=abcd

           [-h|--help]
           [-v|--version]

Example: $0  -t Domain -u abcd\n\n";
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
        'u|user=s'         => \ my $user,
        't|tree=s'         => \ my $tree,
        'l|listoptions'    => \ my $listoptions,
        'h|help'           => \&display_help,
        'v|version'        => sub{ print "This is $0, version " .VERSION. "\n"; exit; }
) or &display_help;
if (defined ($listoptions)) { &list;&display_help;}
if ( (scalar(@ARGV < 0)) || (!defined($tree)) || (!defined($user)) ) {  &display_help; }
if ( (!defined($inifile->{$tree})) || (!defined($inifile->{$tree}->{'base'})) )  { die "[$0]: ERROR: Unknown [ tree || base ] in $configfile"; }


###################
#  Sanity checks  #
###################

if ($user !~ /[a-zA-Z][a-zA-Z0-9]{2,40}/) {
        print "[*] $0: ERROR: group [$user] not string or length not in range(2,40)\n";
        &logit ($logfile, "group [$user] not string or length not in range(2,40)");
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

$opt{'userbase'}     = "ou=users," . $opt{'base'};
$opt{'userbasedn'}   = "uid=$user,ou=users," . $opt{'base'};

&logit ( $logfile, "$0 -u $user -t $tree" );



# make sure user name exist
if (! user_exists ($handle, $user, $opt{'userbase'}) ) {
        print  ( "ERROR: user => [" . $opt{'userbasedn'} . "] does NOT exist!\n");
        &logit ( $logfile, "ERROR: user => [" . $opt{'userbasedn'} . "] does NOT exist!");
        &cleanup;
        exit 1;
}


# remove memberUid user from groups
my @groups = &find_memberUid_groups_of($handle, $user, $opt{'groupbase'});
if (scalar (@groups) > 0 ) {
        foreach my $gname (@groups) {
                my $full_group_dn = "cn=" . $gname . "," . $opt{'groupbase'} ;
                group_remove_memberUid($handle, $user, $full_group_dn);
                #print "Group for memberUid: $gname\n";
        }
}

# remove hMemberDN userDN from groups
my @groups_hMemberDN = &find_hMemberDN_groups_of($handle, $opt{'userbasedn'}, $opt{'groupbase'});
if (scalar (@groups_hMemberDN) > 0 ) {
        foreach my $gname (@groups_hMemberDN) {
                my $full_group_dn = "cn=" . $gname . "," . $opt{'groupbase'} ;
                group_remove_hMemberDN($handle, $opt{'userbasedn'}, $full_group_dn);
                #print "Group for hMemberDN: $gname\n";
        }
}

# remove VmWare uniqueMember userDN from groups
my @groups_uniqueMember = &find_uniqueMember_groups_of($handle, $opt{'userbasedn'}, $opt{'groupbase'});
if (scalar (@groups_uniqueMember) > 0 ) {
        foreach my $gname (@groups_uniqueMember) {
                my $full_group_dn = "cn=" . $gname . "," . $opt{'groupbase'} ;
                group_remove_uniqueMember($handle, $opt{'userbasedn'}, $full_group_dn);
                #print "Group for uniqueMember: $full_group_dn\n";
        }
}

# remove user from tree
if ( user_del ($handle, $opt{'userbasedn'} ) )
{
        &logit($logfile, "SUCCESS: userdel() DELETED user => " . $opt{'userbasedn'} );
} else {
        print ("ERROR: userdel() DELETE  user => " . $opt{'userbasedn'} . "\n");
        &logit($logfile,"ERROR: userdel() DELETE user => " . $opt{'userbasedn'} );
        &cleanup;
        exit 1;
}

# print messages on screen
print "DELETED " . $opt{'userbasedn'} . "\n";
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
                               filter => "(&(objectclass=top)(|(objectclass=posixGroup)(objectclass=groupOfUniqueNames))(cn=$name))"
                             );
        $msg->code && die $msg->error;

        &logit ($logfile, "SUCCESS: group_exists() Checked for existing group cn=$name,$where");

        return ($msg->count);
}

########################################
# Check whether or not the user exists #
########################################
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

##################
# Remove user dn #
##################
sub user_del {
        my ( $ldap, $userdn) = @_;
        my ( $msg );

        $msg = $ldap->delete($userdn);

        if ($msg->code) {
                print ("ERROR: user_del() DELETE: user => $userdn reason: $msg->error");
                &logit ($logfile, "ERROR: user_del() DELETE: user => $userdn, reason: $msg->error");
                return 0;
        } else {
                #print ("SUCCESS: group => $grpbasedn, user => $user, hMemberDN => $userdn");
                &logit ($logfile, "SUCCESS: user_del() DELETE: user => $userdn");
                return 1;
        }

}


#######################################
# find group with memberUid attribute #
#######################################
sub find_memberUid_groups_of {

        my ( $ldap, $user, $where) = @_;
        my @groups = ();

        my ( $msg );

        $msg   = $ldap->search( base   => $where,
                                 filter => "(&(objectclass=posixGroup)(memberuid=$user))"
        );

        $msg->code && die $msg->error;

        my $entry;

        while ( $entry = $msg->shift_entry() ) {
                push( @groups, scalar( $entry->get_value('cn') ) );
        }

        &logit ($logfile, "SUCCESS: find_memberuid_groups_of() groups for user $user => @groups");

        return (@groups);
}

sub group_remove_memberUid {

         my ( $ldap, $user, $groupdn) = @_;
         my $members  = '';

         my ( $msg );

         # delete only the user from the group
         $msg = $ldap->modify( "$groupdn", changes => [
                                                       delete => [
                                                                  memberUid => ["$user"]
                                                                 ]
                                                      ]
        );

        if ($msg->code) {
                print ("ERROR: group_remove_memberuid() DELETE: memberUid => $user from $groupdn reason: $msg->error");
                &logit ($logfile, "ERROR: group_remove_memberuid() DELETE: memberUid $user from $groupdn, reason: $msg->error");
                return 0;
        } else {
                #print ("SUCCESS: group => $grpbasedn, user => $user, hMemberDN => $userdn");
                &logit ($logfile, "SUCCESS: group_remove_memberuid() DELETE: memberUid $user from $groupdn");
                return 1;
        }
}

###############################
# remove hMemberDN from group #
###############################
sub find_hMemberDN_groups_of {

        my ( $ldap, $userdn, $where) = @_;
        my @groups = ();

        my ( $msg );

        $msg   = $ldap->search( base   => $where,
                                filter => "(&(objectclass=posixGroup)(hMemberDN=$userdn))"
        );

        $msg->code && die $msg->error;

        my $entry;

        while ( $entry = $msg->shift_entry() ) {
                push( @groups, scalar( $entry->get_value('cn') ) );
        }

        &logit ($logfile, "SUCCESS: find_hMemberDN_groups_of() groups for user $userdn => @groups");

        return (@groups);
}

sub group_remove_hMemberDN {

         my ( $ldap, $user, $groupdn) = @_;
         my $members  = '';

         my ( $msg );

         # delete only the user from the group
         $msg = $ldap->modify( "$groupdn", changes => [
                                                       delete => [
                                                                  hMemberDN => ["$user"]
                                                                 ]
                                                      ]
        );

        if ($msg->code) {
                print ("ERROR: group_remove_hMemberDN() DELETE: hMemberDN => $user from $groupdn reason: $msg->error");
                &logit ($logfile, "ERROR: group_remove_hMemberDN() DELETE: hMemberDN $user from $groupdn, reason: $msg->error");
                return 0;
        } else {
                #print ("SUCCESS: group => $grpbasedn, user => $user, hMemberDN => $userdn");
                &logit ($logfile, "SUCCESS: group_remove_hMemberDN() DELETE: hMemberDN $user from $groupdn");
                return 1;
        }
}


#########################################
# remove uniqueMember from VmWare group #
#########################################
sub find_uniqueMember_groups_of {

        my ( $ldap, $userdn, $where) = @_;
        my @groups = ();

        my ( $msg );

        $msg   = $ldap->search( base   => $where,
                                filter => "(&(objectclass=groupOfUniqueNames)(uniqueMember=$userdn))"
        );

        $msg->code && die $msg->error;

        my $entry;

        while ( $entry = $msg->shift_entry() ) {
                push( @groups, scalar( $entry->get_value('cn') ) );
        }

        &logit ($logfile, "SUCCESS: find_uniqueMember_groups_of() groups for user $userdn => @groups");

        return (@groups);
}

sub group_remove_uniqueMember {

         my ( $ldap, $user, $groupdn) = @_;
         my $members  = '';

         my ( $msg );

         # delete the user from the group
         $msg = $ldap->modify( "$groupdn", changes => [
                                                       delete => [
                                                                  uniqueMember => ["$user"]
                                                                 ]
                                                      ]
        );

        if ($msg->code) {
                print ("ERROR: group_remove_uniqueMember() DELETE: uniqueMember => $user from $groupdn reason: $msg->error");
                &logit ($logfile, "ERROR: group_remove_uniqueMember() DELETE: uniqueMember $user from $groupdn, reason: $msg->error");
                return 0;
        } else {
                &logit ($logfile, "SUCCESS: group_remove_uniqueMember() DELETE: uniqueMember $user from $groupdn");
                return 1;
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
