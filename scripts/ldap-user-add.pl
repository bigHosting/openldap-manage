#!/usr/bin/perl

#
# (c) Security Guy 2015.01.27, 2015.12.08
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
       #'ldap_expire_account', '180'
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

my %shells = (
        "/bin/bash"      => { name => "/bin/bash",     type => "regular"   },
        "/bin/hsh"       => { name => "/bin/hsh",      type => "regular"   },
        "/sbin/nologin"  => { name => "/sbin/nologin", type => "restricted"}
);

#my %shadow = (
#        "Min"       =>  0,
#        "Max"       =>  180,
#        "Expire"    =>  '-1',
#        "Flag"      =>  0,
#        "Inactive"  =>  '-1',
#        "Warning"   =>  20
#);

sub display_help {
         print "
usage: $0

           -g|--group=security
           -t|--tree=Domain
           -u|--user=abcd
           -s|--shell=/bin/bash
           -e|--email=abcd\@domain.com
           -f|--firstname=John
           -a|--lastname=Doe
           -r|--manager=uid=mymanager,ou=users,o=Domain,dc=domain,dc=com

           [-m|--mobile=1647924000]
           [-o|--otrs=OTRS-12345]
           [-l|--listoptions]
           [-h|--help]
           [-v|--version]

Example: $0  -g security -t Domain -u abcd -s /bin/bash -e abcd\@domain.com -f John -a Doe -r uid=mymanager,ou=users,o=Domain,dc=domain,dc=com\n\n";
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
        'a|lastname=s'     => \ my $lastname,
        'e|email=s'        => \ my $email,
        'f|firstname=s'    => \ my $firstname,
        'g|group=s'        => \ my $group,
        'r|managerdn=s'    => \ my $managerdn,
        'o|otrs=s'         => \ my $otrs,
        's|shell=s'        => \ my $shell,
        't|tree=s'         => \ my $tree,
        'u|user=s'         => \ my $user,
        'm|mobile=i'       => \ my $mobile,
        'l|listoptions'    => \ my $listoptions,
        'h|help'           => \&display_help,
        'v|version'        => sub{ print "This is $0, version " .VERSION. "\n"; exit; }
) or &display_help;
if (defined ($listoptions)) { &list;&display_help;}
if ( (scalar(@ARGV < 0)) || (!defined($email)) || (!defined($firstname)) || (!defined($lastname)) || (!defined($group)) || (!defined($managerdn)) || (!defined($tree)) || (!defined($user)) || (!defined($shell)) ) {  &display_help; }
if ( (!defined($inifile->{$tree})) || (!defined($inifile->{$tree}->{'base'})) )  { die "[$0]: ERROR: Unknown [ tree || base ] in $configfile"; }
if ( !defined ($shells{$shell}->{'name'}) ) { &display_help;}



###################
#  Sanity checks  #
###################
if ($group !~ /[a-zA-Z][a-zA-Z0-9]{2,40}/) {
        print "[*] $0: ERROR: group [$group] not string or length not in range(2,40)\n";
        &logit ($logfile, "group [$group] not string or length not in range(2,40)");
        exit 1;
}

if ($user !~ /[a-zA-Z][a-zA-Z0-9]{2,40}/) {
        print "[*] $0: ERROR: group [$user] not string or length not in range(2,40)\n";
        &logit ($logfile, "group [$user] not string or length not in range(2,40)");
        exit 1;
}

if ($managerdn !~ m/^uid=(.*),ou=users,o=(.*),dc=domain,dc=com$/)
{
        print "[*] $0: ERROR: manager [$managerdn] invalid\n";
        &logit ($logfile, "manager [$managerdn] invalid");
        exit 1;
}
my ($managercn,$managertree) = ($managerdn =~ m/^uid=(.*),ou=users,o=(.*),dc=domain,dc=com$/);
if (!defined($inifile->{$managertree}) )
{
        die "[$0]: ERROR: Unknown manager's tree on cli, does not match entries in $configfile";
}
my ($managerbase) = "ou=users,o=$managertree,dc=domain,dc=com";

my $ticket;
if ( defined ($otrs))
{
        if ($otrs !~ m/(?:OTRS)(?:-)(\d+)$/)
        {
                print "[*] $0: ERROR: otrs [$otrs] invalid\n";
                &logit ($logfile, "otrs [$otrs] invalid");
                exit 1;
        }

        #my ($number) = ($text =~ m{(?:OTRS)(?:-)(\d+)});
        $ticket = $otrs;
} else {
        $ticket = "NA";
}


my ($emailuser, $emaildomain) = ( $email =~ /(.*)@([^@]*)$/ );


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

&logit ( $logfile, "$0 -g $group -s $shell -u $user -t $tree" );

# make sure group does NOT exist
if ( ! group_exists($handle, $group, $opt{'groupbase'}) ) {
        print ( "ERROR: group => [" . $opt{'groupbasedn'} . "] NOT exist!\n");
        &logit ( $logfile, "ERROR: group => [" . $opt{'groupbasedn'} . "] does NOT exist!");
        &cleanup;
        exit 1;
}

# make sure user does NOT exist
if ( user_exists ($handle, $user, $opt{'userbase'}) ) {
        print  ( "ERROR: user => [" . $opt{'userbasedn'} . "] exists!\n");
        &logit ( $logfile, "ERROR: user => [" . $opt{'userbasedn'} . "] exists!");
        &cleanup;
        exit 1;
}


# make sure manager exists
if ( ! user_exists ($handle, $managercn, $managerbase) ) {
        print  ( "ERROR: manager => [" . $managerdn . "] does NOT exist!\n");
        &logit ( $logfile, "ERROR: manager => [" . $managerdn . "] exist!");
        &cleanup;
        exit 1;
}

# set options
$opt{'gid'}   = get_gid ( $handle, $group, $opt{'groupbase'} );
$opt{'uid'}   = get_next_uid($handle);
$opt{'home'}  = sprintf("/home/%s", $user);

$opt{'gecos'}         = "$firstname $lastname";
$opt{'givenName'}     = $firstname;
$opt{'initials'}      = uc(sprintf("%s%s",substr($user, 0, 1),substr($user, 1, 1) ) );
$opt{'userPassClear'} = &rand_pass(10);
$opt{'userPassword'}  = password_ssha($opt{'userPassClear'});

my $mob = "0000000000";
if (defined($mobile)) {
        my $mob = $mobile;
}

if ( ! add_user ($handle, $user, $opt{'userbasedn'} ) )
{
        &logit($logfile, "SUCCESS: NEW user => " . $opt{'userbasedn'} );
} else {
        print ("ERROR: group $group ".$opt{'groupbasedn'}.", user => " . $opt{'userbasedn'} . "\n");
        &logit($logfile,"ERROR: group $group ".$opt{'groupbasedn'}.", user => " . $opt{'userbasedn'} );
        &cleanup;
        exit 1;
}

if ( ! add_user_to_group ($handle, $user, $opt{'userbasedn'},$group, $opt{'groupbasedn'}) )
{
        &logit($logfile, "SUCCESS: NEW user => " . $opt{'userbasedn'} );
} else {
        print ("ERROR: group $group ".$opt{'groupbasedn'}.", user => " . $opt{'userbasedn'} . "\n");
        &logit($logfile,"ERROR: group $group ".$opt{'groupbasedn'}.", user => " . $opt{'userbasedn'} );
        &cleanup;
        exit 1;
}


print "User: " . $opt{'userbasedn'} . " added with Password: '" . $opt{'userPassClear'} . "'\n";
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

sub get_next_uid {
        my ( $ldap ) = @_;
        my ( $msg ) ;

        my %uidhash = ();

        $msg = $ldap->search ( base => $opt{'base'},
                               attrs => ['cn', 'uidNumber'],
                               filter => "(&(objectclass=top)(objectclass=posixAccount)(objectclass=shadowAccount))"
        );

        $msg->code && die $msg->error;

        if ( ! $msg->count ) {
                die "[*] $0: ERROR: get_next_uid() cannot search thru " . $opt{'base'} . "\n";
                #return -1;
        }

        # Loop thru all the groups
        foreach my $entry ($msg->entries) {
                # Grab the cn and uidnumber
                my($tmpcn) = $entry->get('cn');
                my($tmpnum) = $entry->get('uidNumber');
                # Build up a hash of cn and uidNumber
                $results{$tmpcn} = $tmpnum;
                #print "$tmpcn => $tmpnum\n";
        }

        # Sort the groups by gid
        my @uids = sort bygroup keys %results;
        # Then get the last one, and add one to it.
        my $lastuid = $results{$uids[$#uids]};
        my $nextuid = $lastuid + 1;
        &logit ($logfile, "SUCCESS: get_next_uid() existing UID: $lastuid, new UID: $nextuid");

        return $nextuid;

}

sub bygroup {
        $results{$a} <=> $results{$b}
}

## Add new group
sub add_user {
        my ( $ldap, $user, $userdn) = @_;
        my ( $msg );

        $msg = $ldap->add(
                          dn   => $userdn,
                          attr => [
                                      'uidNumber'                       =>      $opt{'uid'},
                                      'gidNumber'                       =>      $opt{'gid'},
                                      'loginShell'                      =>      $shell,
                                      'objectClass'                     =>      [ 'hSecurity', 'inetOrgPerson', 'shadowAccount', 'posixAccount', 'top' ],
                                      'description'                     =>      $opt{'groupbasedn'},
                                      'hAccountInitialSetup'            =>      '0',
                                      'hAccountSetupDate'               =>      &SelfServiceLastPasswordChange,
                                      'hPasswordSecretA'                =>      "NOTSETUP",
                                      'hPasswordSecretB'                =>      "NOTSETUP",
                                      'hStatus'                         =>      '0',
                                      'hOTRS'                           =>      $ticket,
                                      'SelfServiceLastPasswordChange'   =>      &SelfServiceLastPasswordChange,
                                      'homeDirectory'                   =>      $opt{'home'},
                                      'gecos'                           =>      $opt{'gecos'},
                                      'givenName'                       =>      $opt{'givenName'},
                                      'initials'                        =>      $opt{'initials'},
                                      'cn'                              =>      $user,
                                      'sn'                              =>      $lastname,
                                      'mail'                            =>      $emailuser . "\@" . $emaildomain,
                                      'mobile'                          =>      $mob,
                                      'telephoneNumber'                 =>      "0000000000",
                                      'title'                           =>      $userdn,
                                      'uid'                             =>      $user,
                                      'userPassword'                    =>      $opt{'userPassword'},
                                      'shadowExpire'                    =>      &shadowExpire,
                                      'manager'                         =>      $managerdn
                                  ]
        );

        if ($msg->code) {
                print ("ERROR: add_user() user => $user, DN => $userdn reason: $msg->error");
                &logit ($logfile, "ERROR: add_user() user => $user, DN => $userdn, reason: $msg->error");
                return 1;
        } else {
                &logit ($logfile, "SUCCESS: add_user() user => $user, DN => $userdn SUCCESS");
                return 0;
        }

}

# get group id from group name
sub get_gid {
        my ( $ldap, $name, $base ) = @_;
        my ( $msg, $entry );

        $msg = $ldap->search ( base => $base, filter => "(&(cn=$name)(|(objectclass=posixGroup)(objectclass=groupOfUniqueNames)))" );
        if ($msg->code) {
                warn $msg->error;
                return -1;
        }

        if (!$msg->count) { return -1; }

        if ($msg->count > 1) {
                warn "More than one entry returned for (cn=$name) when searching base";
                warn "$group";
        }

        $entry = $msg->entry(0);

        if (!defined($entry->get_value('gidNumber'))) {
                return -1;
        }
        else {
                &logit ($logfile, "SUCCESS: gid_exists() Checked for existing gid for group $name");
                return $entry->get_value('gidNumber');
        }
}

sub add_user_to_group {
        my ( $ldap, $user, $userdn, $group, $groupdn) = @_;
        my ( $msg );

        #print "DEBUG: user_add_description() user: $user, userdn: $userdn, newentry: $newentry\n";

        $msg = $ldap->modify($groupdn, add => {
                                                 memberUid => "$user",
                                                 hMemberDN => "$userdn"
                                               }
        );

        if ($msg->code) {
                print ("ERROR: add_user_to_group() user => $userdn, memberUid => $user, hMemberDN => $userdn reason: $msg->error");
                &logit ($logfile, "ERROR: add_user_to_group() user => $userdn, memberUid => $user, hMemberDN => $userdn reason: $msg->error");
                return 1;
        } else {
                &logit ($logfile, "SUCCESS: add_user_to_group() user => $userdn, memberUid => $user, hMemberDN => $userdn");
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

        print "SHELLS: ";
        foreach my $key (keys %shells)
        {
                print $shells{$key}->{'name'} . " ";
        }
        print "\n";

        print "TREES: ";
        while( my( $key, $val ) = each %{$inifile} ) {
                print $key . " ";
        }
        print "\n";

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

sub get_salt8 {
        my $salt = join '', ('a'..'z')[rand 26,rand 26,rand 26,rand 26,rand 26,rand 26,rand 26,rand 26];
        return($salt);
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

sub shadowExpire {
        #return int( ( time() / 86400) + $settings{'ldap_expire_account'} );
        # add expired account until account gets set up by the user
        return int( ( time() / 86400) -1 );
}

sub SelfServiceLastPasswordChange {
        my (undef,undef,undef,$mday,$mon,$year,undef,undef,undef) = localtime(time);
        $year += 1900;
        $mon  = sprintf("%02d", $mon+1);
        $mday = sprintf("%02d", $mday);
        return ($year . $mon . $mday);
}

