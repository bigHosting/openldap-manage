#!/usr/bin/perl

#
# (c) SecurityGuy 2015.01.22
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


my %branches = (
        "affiliates"   => { name => "affiliates",  type => "dc", base => "dc=affiliates,dc=domain,dc=com" },
        "vendors"      => { name => "vendors",     type => "dc", base => "dc=vendors,dc=domain,dc=com"    },
        "ACME"         => { name => "ACME",        type => "o",  base => "o=ACME,dc=domain,dc=com"        },
        "MYDOMAIN"     => { name => "MYDOMAIN",    type => "o",  base => "o=MYDOMAIN,dc=domain,dc=com"    }
);

my %dirs = (
        "ldap" => "/localservices/accounts/accounts/ldap",
        "logs" => "/localservices/accounts/accounts/logs"
);


sub display_help {
         print "
usage: $0  -n|--name=Deluxe  -b|--branch=affiliates  -d|--groupdescription [-h|--help] [-v|--version]

       $0  -n Deluxe -b affiliates -d 6000-7000
       $0  -n ATT    -b vendors -d 3000-4000\n\n";
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


# exiting cleanly from an LDAP connection
$SIG{__DIE__} = 'cleanup';

# Define config filename as <application_name>.conf
#(my $configfile = "/etc/" . basename($0)) =~ s/^(.*?)(?:\..*)?$/$1.conf/;
(my $logfile   = $dirs{"logs"} . "/" . basename($0)) =~ s/^(.*?)(?:\..*)?$/$1.log/;

my(%results) = ();

#Determine arguments
GetOptions( \ my %options,
        'b|branch=s'       => \ my $branch,
        'd|description=s'  => \ my $description,
        'n|name=s'         => \ my $name,
        'l|listoptions'    => \ my $listoptions,
        'h|help'           => \ &display_help,
        'v|version'        =>   sub{ print "This is $0, version " .VERSION. "\n"; exit; }
) or &display_help;

&display_help if ( (scalar(@ARGV < 0)) || (!defined($name)) || (!defined($branch)) || (!defined($branch)) || (!defined($description)) );
&display_help if ( !defined ($branches {$branch}) );


&logit ( $logfile, "----------------------------" );

###################
#  Sanity checks  #
###################
if ($name !~ /[a-zA-Z][a-zA-Z0-9]{3,20}/) {
        print "[*] $0: ERROR: branch [$name] not string or length not in range(3,20)\n";
        exit (1);
}

# match description, split by '-' into 2 vars so we can check if they are numeric
my ($range1, $range2) = ($description =~ m{(\d+)-(\d+)});
if ( ($range1 !~ /^\d+?$/) || ($range2 !~ /^\d+?$/) || ($range1  >  $range2)  ) {
        print "[*] $0: ERROR: (range [$description] not numeric) or (incorrect range) or (second number > first)\n";
        exit (1);
}

while( my( $name, $folder ) = each %dirs ) {
        rmkdir($folder) if (! -d $folder);;
}

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
$result->code() && die $result->error();

my %newtree = ();
$newtree{'basedn'} = $branches {$branch}->{'base'}; 
$newtree{'dn'}     = "o=" . $name . "," . $branches {$branch}->{'base'}; 

&logit ( $logfile,"$0 -n $name -b $branch -d $description" );

if (! tree_exists ($handle, $name) ) {
        tree_create ($handle, $name, $newtree{'dn'});
} else {
        print "[*] $0: WARN: branch [" . $newtree{'dn'} . "] already exists\n";
        &logit ( $logfile,"WARN: branch [" . $newtree{'dn'} . "] already exists" );
}

# create applications, groups, hosts, users, sudoers
my @subtree = ('applications','groups','hosts','users','sudoers');
foreach my $item (@subtree) {
        if ( subtree_exists($handle, $newtree{'dn'}, $item) ) {
                print "[*] $0: WARN: subtree [$item] in DN [" . $newtree{'dn'} ."] already exists!\n";
        } else {
                subtree_create ($handle, $item, $newtree{'dn'});
        }
}

# close connection to ldap
&cleanup;
exit(0);


####################
#  LDAP FUNCTIONS  #
####################

## Check whether or not the user already existed in the directory
sub subtree_exists {
        my ( $ldap, $mytree, $name ) = @_;
        my ( $msg );

        &logit ($logfile, "Checked for existing subtree $name => $mytree");

        # we should add scope => "one" to search one level only
        $msg = $ldap->search ( base => $mytree,
                               filter => "(&(objectclass=top)(objectclass=organizationalUnit)(ou=$name))" );
        $msg->code && die $msg->error;


        return ($msg->count);
}

## Check whether or not the user already existed in the directory
sub tree_exists {
        my ( $ldap, $treename) = @_;
        my ( $msg );

        &logit ($logfile, "Checking for existing tree => $treename");

        # we should add scope => "one" to search one level only
        $msg = $ldap->search ( base => $newtree{'basedn'},
                               filter => "(&(objectclass=top)(objectclass=organization)(o=$treename))" 
        );
        $msg->code && die $msg->error;

        return ($msg->count);
}

# Add new branch
sub tree_create {
        my ( $ldap, $name, $dn) = @_;
        my ( $msg );

        # we should add scope => "one" to search one level only
        $msg = $ldap->add( dn => $dn,
                           attr => [
                                    'o' => "$name",
                                    'objectClass' => [ 'organization','top']
                                   ]
        );

        if ($msg->code) {
                print "[*] ERROR: branch add [$name] => [$dn] failed w $msg->error\n";
                &logit ($logfile, "ERROR: branch add $name => [$dn] reason: $msg->error");
                return 1;
        } else {
                print "[*] INFO: branch add [$name] => [$dn] SUCCESS\n\n";
                &logit ($logfile, "SUCCESS: Added branch $name => $dn");
                return 0;
        }

}

# Add subtree
sub subtree_create {
        my ( $ldap, $name, $dn) = @_;
        my ( $msg );

        $dn = "ou=" . $name . "," . $dn;

        if ($name =~ m/groups/) {
                $msg = $ldap->add( dn => $dn,
                                   attr => [
                                       'ou' => "$name",
                                       'description' => "Group ID Range $description",
                                       'objectClass' => [ 'organizationalUnit','top']
                                           ]
                );

        } else {
                $msg = $ldap->add( dn => $dn,
                                   attr => [
                                       'ou' => "$name",
                                       'objectClass' => [ 'organizationalUnit','top']
                                           ]
                );

        }

        if ($msg->code) {
                print "[*] ERROR: subranch add [$name] => [$dn]: $msg->error\n";
                &logit ($logfile, "ERROR: subbranch add $name => $dn: $msg->error");
                return 1;
        } else {
                print "[*] INFO: subbranch add [$name] => [$dn] SUCCESS\n\n";
                &logit ($logfile, "SUCCESS: Added subbranch $name => $dn");
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


