#!/usr/bin/perl

#
# (c) Security Guy 2015.01.21
#

$| = 1;

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
usage: $0  -t|--tree=Domain  -u|--user=abcd   [-p|--password=fgg\$oR%J+M]  [-l|--listoptions]  [-h|--help]  [-v|--version]

       $0  -t Domain -u abcd\n\n";
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

sub get_salt8 {
        my $salt = join '', ('a'..'z')[rand 26,rand 26,rand 26,rand 26,rand 26,rand 26,rand 26,rand 26];
        return($salt);
}

sub password_ssha {
        my $pass=shift;
        use Digest::SHA1;
        use MIME::Base64;
        my ($hashedPasswd,$salt);
        $salt = &get_salt8;
        my $ctx = Digest::SHA1->new;
        $ctx->add($pass);
        $ctx->add($salt);
        $hashedPasswd = '{SSHA}' . encode_base64($ctx->digest . $salt,'');
        return($hashedPasswd);
}

sub rand_pass
{
        my $length=shift;

        my @chars=('a'..'z','A'..'Z','0'..'9','_','@','&','.',',',' ');
        my $random_string;
        foreach (1..$length)
        {
               $random_string.=$chars[rand @chars];
        }
        return $random_string;
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
        'p|password=s'     => \ my $pass,
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
        print "[*] $0: ERROR: user [$user] not string or length not in range(2,40)\n";
        exit 1;
}

while( my( $name, $folder ) = each %dirs ) {
        rmkdir($folder) if (! -d $folder);;
}
# log cli options
&logit ( $logfile, "----------------------------" );
my $shadow;

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

$opt{'userbase'}     = "ou=users," . $opt{'base'};
$opt{'userbasedn'}   = "uid=$user,ou=users," . $opt{'base'};

&logit ( $logfile, "$0 -u $user -t $tree" );

# make sure user name exist
if ( ! user_exists ($handle, $user, $opt{'userbase'}, $opt{'userbasedn'}) ) {
        print "[*] $0: ERROR: user_exists() user [$user] does NOT exist!\n";
        &logit ( $logfile, "ERROR: user_exists() user [$user] does NOT exist!");
        &cleanup;
        exit 1;
}

if (!defined ($pass) ) {
        $opt{'userPassClear'} = &rand_pass(10);
} else {
        $opt{'userPassClear'} = $pass;
}
$opt{'userPassword'}  = password_ssha($opt{'userPassClear'});

if ( user_has_shadow_lastchange ($handle, $user, $opt{'userbasedn'} ) ) {
        $shadow = 1;
}

if ( user_change_password ($handle, $user, $opt{'userbasedn'}, $opt{'userPassword'} ) ) {
        print "[*] $0: ERROR: user_change_password() user [$user] userPassword change failed!\n";
        &logit ( $logfile, "ERROR: user_change_password() [$user] userPassword change failed!");
        &cleanup;
        exit 2;
} else {
        print "[*] $0: SUCCESS: user_change_password() user dn [" . $opt{'userbasedn'} . "] new password '" . $opt{'userPassClear'} ."'  (without single quotes)\n";
}

print "SUCCESS: tail $logfile\n";

# close connection to ldap
&cleanup;
exit(0);


####################
#  LDAP FUNCTIONS  #
####################

## Check whether or not the user exists
sub user_exists {
        my ( $ldap, $name, $where, $fulldn ) = @_;
        my ( $msg );

        $msg = $ldap->search ( base   => $where,
                               scope  => "one",
                               filter => "(&(objectclass=top)(objectclass=posixAccount)(objectclass=inetOrgPerson)(objectclass=hSecurity)(uid=$name))"
                             );
        $msg->code && die $msg->error;

        &logit ($logfile, "SUCCESS: user_exists() Checked for existing user $name => $where");

        return ($msg->count);
}

## Check whether or not the user has shadowLastChange attribute
sub user_has_shadow_lastchange {
        my ( $ldap, $user, $userdn, $groupdn ) = @_;
        my ( $msg );

        $msg = $ldap->search ( base   => $userdn,
                               scope  => "base",
                               filter => "(&(uid=$user)(shadowLastChange=*))"
                             );
        $msg->code && die $msg->error;

        &logit ($logfile, "SUCCESS: user_has_shadow_lastchange() Checked for existing shadowLastChange=* in => $userdn");

        return ($msg->count);
}

## Set hStatus=5 to the user
sub user_change_password {
        my ( $ldap, $user, $userdn, $password) = @_;
        my ( $msg );

        if(!defined($shadow)) {
                $msg = $ldap->modify($userdn, replace => { userPassword => "$password" } );
        } else {
                my $shadowLastChange = int(time() / 86400);
                $msg = $ldap->modify($userdn, replace => { userPassword => "$password", shadowLastChange => "$shadowLastChange" } );
        }

        if ($msg->code) {
                &logit ($logfile, "ERROR: user_change_password() user => $user, DN => $userdn, userPassword change failed reason: $msg->error");
                return 1;
        } else {
                &logit ($logfile, "SUCCESS: user_change_password() user => $user, DN => $userdn, userPassword change OK");
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

