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


#my %shells = (
#        "/bin/bash"      => { name => "/bin/bash",     type => "regular"   },
#        "/sbin/nologin"  => { name => "/sbin/nologin", type => "restricted"}
#);

my %dirs = (
        "ldap" => "/localservices/accounts/accounts/ldap",
        "logs" => "/localservices/accounts/accounts/logs"
);


sub display_help {
         print "
usage: $0  -n|--nameOfGroup=accounting  -t|--tree=Domain [-g|--gid=1017]  [-w|--vmware]  [-l|--listoptions]  [-h|--help] [-v|--version]

       $0  -n accounting -t Domain\n\n";

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


# exiting cleanly from an LDAP connection
$SIG{__DIE__} = 'cleanup';

# Define config filename as <application_name>.conf
#(my $configfile = "/etc/" . basename($0)) =~ s/^(.*?)(?:\..*)?$/$1.conf/;
my $configfile = "/etc/ldapHostopia.conf";
my $inifile    = iniRead($configfile);
(my $logfile   = $dirs{"logs"} . "/" . basename($0)) =~ s/^(.*?)(?:\..*)?$/$1.log/;

my(%results) = ();

#Determine arguments
GetOptions( \ my %options,
        'g|gid=i'          => \ my $gid,
        'n|nameOfGroup=s'  => \ my $groupname,
        't|tree=s'         => \ my $tree,
        'l|listoptions'    => \ my $listoptions,
        'h|help'           => \&display_help,
        'w|vmware'         => \ my $vmware,
        'v|version'        => sub{ print "This is $0, version " .VERSION. "\n"; exit; }
) or &display_help;
if (defined ($listoptions)) {
        #print "\nOPTIONS\n\n";
        #print "[$0]:\tSHELLS:\t";
        #foreach my $key (keys %shells)
        #{
        #        print $shells{$key}->{'name'} . " ";
        #}
        print "\n";

        print "TREES: ";
        while( my( $key, $val ) = each %{$inifile} ) {
                print $key . " ";
        }
        print "\n";

        &display_help;
}
&display_help if ( (scalar(@ARGV < 0)) || (!defined($groupname)) || (!defined($tree)) );
#&display_help if ( !defined ($shells{$shell}->{'name'}) );
die "[$0]: ERROR: Unknown [ tree || base ] in $configfile" if ( (!defined($inifile->{$tree})) || (!defined($inifile->{$tree}->{'base'}))  );

###################
#  Sanity checks  #
###################
if ($groupname !~ /[a-zA-Z][a-zA-Z0-9]{3,20}/) {
        print "[*] $0: ERROR: group [$groupname] not string or length not in range(3,20)\n";
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


my %group = ();
$group{'basedn'} = "o=" . $inifile->{$tree}->{'base'};
$group{'dn'}     = "cn=$groupname,ou=groups," . $group{'basedn'};

# if group gid not specified on cli then generate next gid from ldap
if (!defined($gid)) {
        $gid = &get_next_gid($handle);
}

# safety checlks
if (($gid > 65535) || ($gid < 1000)) {
        print "[*] $0: ERROR: gid [$gid] < 0 or > 65535\n";
        exit 1;
}

&logit ( $logfile, "$0 -g $gid -n $groupname -t $tree" );

# make sure group name does not exist
if ( group_exists($handle, $groupname) ) {
        print "[*] $0: ERROR: group [$groupname] already exists!\n";
        &logit ( $logfile, "ERROR: group [$groupname] already exists!");
        &cleanup;
        exit 2;
}

# make sure group gid does not exist
if ( gid_exists($handle, $gid) ) {
        print "[*] $0: ERROR: gid [", $gid, "] already exists!\n";
        &logit ( $logfile, "ERROR: gid [", $gid, "] already exists!");
        &cleanup;
        exit 3;
}

# lets add the new group
if ( group_add($handle, $gid, $groupname, $group{'dn'} ) ) {
        print "[*] $0: ERROR: group [$groupname], gid [", $gid, "] group_add failed!\n";
        &logit ( $logfile, "ERROR: group [$groupname], gid [", $gid, "] group_add failed!");
        &cleanup;
        exit 4;
}

print "SUCCESS: tail $logfile\n";

# close connection to ldap
&cleanup;
exit(0);


####################
#  LDAP FUNCTIONS  #
####################

## Check whether or not the user already existed in the directory
sub group_exists {
        my ( $ldap, $name ) = @_;
        my ( $msg );

        $msg = $ldap->search ( base => $group{'basedn'}, filter => "(&(objectclass=top)(|(objectclass=groupOfUniqueNames)(objectclass=posixGroup))(cn=$name))" );
        $msg->code && die $msg->error;

        &logit ($logfile, "SUCCESS: Checked for existing group $name,$group{'basedn'}");

        return ($msg->count);
}

## Check whether or not the user already existed in the directory
sub gid_exists {
        my ( $ldap, $gid) = @_;
        my ( $msg );

        $msg = $ldap->search ( base => $group{'basedn'}, filter => "(gidNumber=$gid)" );
        $msg->code && die $msg->error;

        &logit ($logfile, "SUCCESS: Checked for existing gid $gid => $group{'basedn'}");

        return ($msg->count);
}

## Add new group
sub group_add {
        my ( $ldap, $gid, $grp, $dn) = @_;
        my ( $msg );

        my(@objectclass) = ();

        if (!defined($vmware)) {
                # regular posix group
                @objectclass = [ 'posixGroup', 'top' ];

                $msg = $ldap->add( dn => $dn,
                                   attr => [
                                           'cn' => "$grp",
                                           'gidNumber' => $gid,
                                           'objectClass' => @objectclass,
                                           'description' => "$grp Group"
                                           ]
                );

        } else {
                # vmware groupOfUniqueNames group . extensibleObject added to be able to have gidNumber
                @objectclass = [ 'extensibleObject','groupOfUniqueNames', 'top' ];

                $msg = $ldap->add( dn => $dn,
                                   attr => [
                                           'cn' => "$grp",
                                           'gidNumber' => $gid,
                                           'objectClass' => @objectclass,
                                           'description' => "$grp Group",
                                           'uniqueMember' => "uid=nonexistent,ou=users,o=Hostopia,dc=domain,dc=com"
                                           ]
                );

        }

        if ($msg->code) {
                print "[*] ERROR: group_add() [$grp] w gid [$gid] and dn [$dn] failed w $msg->error\n";
                &logit ($logfile, "ERROR: group_add() failed group $grp w gid $gid and dn [$dn] reason: $msg->error");
                return 1;
        } else {
                print "[*] SUCCESS: group_add() [$grp] w gid [$gid] and dn [$dn]\n";
                &logit ($logfile, "SUCCESS: group_add() Added $grp w gid $gid");
                return 0;
        }

}
## get the next available gid from the idPool
sub get_next_gid {
        my ( $ldap ) = @_;
        my ( $msg ) ;
        my %gidhash = ();

        $msg = $ldap->search ( base => $group{'basedn'}, filter => "(&(objectclass=top)(|(objectclass=posixGroup)(objectclass=groupOfUniqueNames)))" );
        $msg->code && die $msg->error;

        if ( ! $msg->count ) {
                &cleanup;
                die "[*] $0: ERROR: cannot search thru " . $group{'basedn'} . "\n";
                #return -1;
        }

        # Loop thru all the groups
        foreach my $entry ($msg->entries) {
                # Grab the cn and gidnumber
                my($tmpcn) = $entry->get('cn');
                my($tmpnum) = $entry->get('gidnumber');
                # Build up a hash of cn and gid
                $results{$tmpcn} = $tmpnum;
                #print "$tmpcn => $tmpnum\n";
        }

        # Sort the groups by gid
        my @gids = sort bygroup keys %results;
        # Then get the last one, and add one to it.
        my $lastgid = $results{$gids[$#gids]};
        my $nextgid = $lastgid + 1;
        &logit ($logfile, "SUCCESS: get_next_gid() existing GID: $lastgid, new GID: $nextgid");

        return $nextgid;

}

sub bygroup {
        $results{$a} <=> $results{$b}
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


