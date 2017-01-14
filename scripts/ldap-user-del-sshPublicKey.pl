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
usage: $0   -t|--tree=Domain  -u|--user=abcd  -s|--sshPublicKey='ssh-rsa AAAA.....'   [-h|--help] [-v|--version]

       $0  -t Domain -u abcd -s 'ssh-rsa AAAA....'\n\n";
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

my $configfile = "/etc/ldapHostopia.conf";
my $inifile    = iniRead($configfile);
(my $logfile   = $dirs{"logs"} . "/" . basename($0)) =~ s/^(.*?)(?:\..*)?$/$1.log/;

my(%results) = ();

my @reserved_users = (
    "adm",     "apache",    "avahi",     "avahi-autoipd",
    "bin",     "cacti",     "coremedia", "daemon",
    "dbus",    "exim",      "ftp",       "games",
    "gopher",  "haldaemon", "halt",      "jboss",
    "lp",      "mail",      "mailnull",  "mysql",
    "named",   "news",      "nfsnobody", "nobody",
    "nscd",    "ntp",       "operator",  "pcap",
    "puppet",  "reports",   "root",      "rpc",
    "rpcuser", "rrdcached", "shutdown",  "smmsp",
    "splunk",  "sshd",      "svn",       "sync",
    "tomcat",  "uucp",      "vcsa",      "xfs",
    "zabbix"
);

#Determine arguments
GetOptions( \ my %options,
        's|sshPublicKey=s' => \ my $sshPublicKey,
        'u|user=s'         => \ my $user,
        't|tree=s'         => \ my $tree,
        'h|help'           => \&display_help,
        'v|version'        => sub{ print "This is $0, version " .VERSION. "\n"; exit; }
) or &display_help;
if ( (scalar(@ARGV < 0)) || (!defined($tree)) || (!defined($sshPublicKey)) || (!defined($user)) ) {  &display_help; }
if ( (!defined($inifile->{$tree})) || (!defined($inifile->{$tree}->{'base'})) )  { die "[$0]: ERROR: Unknown [ tree || base ] in $configfile"; }


###################
#  Sanity checks  #
###################
my ($sshkey_header, $sshkey_type, $sshkey_sign) = '';
$sshPublicKey ||= '';

# remove trailing spaces
$sshPublicKey =~ s/^\s+//;
$sshPublicKey =~ s/\s+$//;

if ( length($sshPublicKey) == 0 )
{
        print "[*] $0: ERROR: ssh key [$sshPublicKey] is empty.\n";
        exit(1);
}

# count the number of paces
my ($number) = scalar( @{[ $sshPublicKey =~ /\s/g ]} );

if ( $number == 0 || $number >= 3 )
{
        print "[*] $0: ERROR: ssh key [$sshPublicKey] not in expected format! Too few or too many spaces.\n";
        exit(1);
}

# check for ssh key format: "ssh-rsa AAAAB3NzaC1yc2EAAAA...." or "ssh-ed25519 AAAAC3NzaC1lZDI.... user@domain.com"
($sshkey_header, $sshkey_type, $sshkey_sign) = ($sshPublicKey =~ m{(ssh)(?:-)(\w+)(?:\s)(.*)});
if ( ! ( ($sshkey_header) || ($sshkey_type) || ($sshkey_sign) ) )
{
        print "[*] $0: ERROR: ssh key [$sshPublicKey] not in expected format!\n";
        exit(1);
}

# check username format
if ($user !~ /[a-zA-Z][a-zA-Z0-9]{2,40}/) {
        print "[*] $0: ERROR: group [$user] not string or length not in range(2,40)\n";
        exit 1;
}

# check for restricted users
if ( grep /^${user}$/, @reserved_users ) {
        print "[*] $0: ERROR: user [$user] restricted!\n";
        exit 1;
}

# check if log folder exists.
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

my $objectclass = 0;
my %opt = ();

$opt{'base'}         = "o="                  . $inifile->{$tree}->{'base'};
$opt{'userbase'}     = "ou=users,"           . $opt{'base'};
$opt{'userbasedn'}   = "uid=$user,ou=users," . $opt{'base'};


&logit ( $logfile, "$0 -u $user -t $tree -s \"$sshPublicKey\"" );

# make sure user name exist
if ( ! user_exists ($handle, $user, $opt{'userbase'}) ) {
        print  ( "ERROR: user => [" . $opt{'userbasedn'} . "] does NOT exist!\n");
        &logit ( $logfile, "ERROR: user_exists() user => [" . $opt{'userbasedn'} . "] does NOT exist!");
        &cleanup;
        exit(1);
}

# check if objectclass=ldapPublicKey exists for the user
if ( ! user_has_objectclass ($handle, $user,  $opt{'userbasedn'} ) ) {
        &logit ( $logfile, "INFO: user_has_objectclass() objectclass=ldapPublicKey missing for user " . $opt{'userbasedn'} );
        print ( "INFO: user_has_objectclass objectclass=ldapPublicKey missing for user " . $opt{'userbasedn'} . "\n" );
        exit(1);
} else {
        &logit ( $logfile, "INFO: user_has_objectclass() objectclass=ldapPublicKey exists for user " . $opt{'userbasedn'} );
        $objectclass = 1;
}

# if objectclass=ldapPublicKey exists check to see how many keys we have ( mandatory 1 )
if ($objectclass)
{
        # get the keys from ldap
        my @ssh_keys = &get_ssh_keys ($handle, $user,  $opt{'userbase'} );
        &logit ( $logfile, "INFO: found number of ssh keys: " . scalar (@ssh_keys) . " for user " . $opt{'userbasedn'} );

        # count number of keys
        my $numkeys = scalar ( @ssh_keys );

        # compare each key with the one provided on cli
        foreach my $key (@ssh_keys)
        {
                # check if key exists in ldap
                if ( ! grep /$sshkey_sign/, @ssh_keys ) {
                        print "[*] $0: ERROR: existing key [$key] NOT found in LDAP!\n";
                        &logit ( $logfile, "ERROR: existing key [$key] NOT found for user " . $opt{'userbasedn'} );
                        &cleanup;
                        exit(1);
                }

                # delete ssh key
                if ( ! &del_key ($handle, $user, $opt{'userbasedn'}, $numkeys ) )
                {
                        &logit ( $logfile, "SUCCESS: userdn => ".$opt{'userbasedn'} . ", ssh key =>  " . $sshPublicKey );
                        print ( "SUCCESS: del_key userdn => ".$opt{'userbasedn'} . ", ssh key =>  " . $sshPublicKey . " deleted\n" );
                        &cleanup;
                        exit(0);
                } else {
                        print ( "ERROR: del_key userdn => ".$opt{'userbasedn'}.", ssh key => " . $sshPublicKey . "\n" );
                        &cleanup;
                        exit(1);
                }
        }
}

print "SUCCESS: tail $logfile\n";

####################
#  LDAP FUNCTIONS  #
####################

## Check whether or not the user exists
sub user_exists {
        my ( $ldap, $name, $where ) = @_;
        my ( $msg );

        $msg = $ldap->search ( base   => $where,
                               scope  => "one",
                               filter => "(&(objectclass=top)(objectclass=posixAccount)(objectclass=inetOrgPerson)(objectclass=hSecurity)(uid=$name))"
                             );
        $msg->code && die $msg->error;

        return ($msg->count);
}

## Check whether or not the user exists
sub user_has_objectclass {
        my ( $ldap, $user, $userdn ) = @_;
        my ( $msg );

        $msg = $ldap->search ( base   => $userdn,
                               scope  => "base",
                               filter => "(&(uid=$user)(objectclass=ldapPublicKey))"
                             );
        $msg->code && die $msg->error;

        return ($msg->count);
}

## remove ssh key
sub del_key {
        my ( $ldap, $user, $userdn, $number_of_keys) = @_;
        my ( $msg );

        # if we have multiple keys then we can delete existing one
        if ( $number_of_keys > 1) {
                $msg = $ldap->modify($userdn, delete => {
                                                      sshPublicKey => "$sshPublicKey"
                                                     }
                                    );
        } else {
        # if we have only one key we set it to ''
                $msg = $ldap->modify($userdn, delete => {
                                                      sshPublicKey => "$sshPublicKey",
                                                      objectclass  => "ldapPublicKey"
                                                     }
                                    );
        }
        if ($msg->code)
        {
                &logit ($logfile, "ERROR: del_key() user => $userdn, sshPublicKey => $sshPublicKey reason: $msg->error");
                return 1;
        } else {
                &logit ($logfile, "SUCCESS: del_key() user => $userdn, sshPublicKey => $sshPublicKey");
        }

        return 0;
}


# return found keys
sub get_ssh_keys {
        my ( $ldap, $user, $userdn ) = @_;
        my ( $msg );

        $msg = $ldap->search ( base   => $userdn,
                               cope  => "base",
                               filter => "(&(objectClass=posixAccount)(cn=$user)(objectclass=ldapPublicKey))",
                               attrs  => ['sshPublicKey']
                             );
        $msg->code && die $msg->error;

        my $userdetails = $msg->entry(0);

        # there could be multiple keys
        my @keys = $userdetails->get_value('sshPublicKey');

        return (@keys);
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

