#!/usr/bin/perl

use strict;
use warnings;

use Net::LDAP;
use Net::LDAPS;
use Term::ReadKey;
use POSIX qw/strftime mktime/;
use Sys::Hostname;

my %settings = (
       'binddn' ,      'cn=hsecurity,dc=domain,dc=com',
       'ldap_port',    '636',
       'ldap_version', '3',
       'ldap_debug',   '0',
       'ldap_timeout', '30',
       'base',         'dc=domain,dc=com'
);
$settings{'host'} = hostname;

sub DateToSeconds {
        my ($day, $month, $year) = @_;
        $year -= 1900; # we need this for epoch time since 1970
        return mktime 0, 0, 0, $day, $month, $year;
}
sub rand_range {
        my ($x, $y) = @_;
        return int(rand($y - $x)) + $x;
}
sub get_password {
        print 'Enter password: ';
        ReadMode('noecho');
        my $pass = ReadLine(0);
        chomp $pass;
        ReadMode(0);
        return ($pass);
}


my %today = ();
(undef, undef, undef, $today{'day'}, $today{'month'}, $today{'year'}, undef, undef, undef) = localtime;
$today{'year'} += 1900;
$today{'now'}   = DateToSeconds ( $today{'day'}, $today{'month'}, $today{'year'} );

my $password = &get_password();

my $users_total = 0;
my $users_mod   = 0;

my $ldap = Net::LDAPS->new(
         $settings{'host'},
         verify  => "none",
         onerror => 'warn',
         port    => $settings{'ldap_port'},
         version => $settings{'ldap_version'},
         debug   => $settings{'ldap_debug'},
         timeout => $settings{'ldap_timeout'},
) or die "Can not connect ldap: $@";

# Bind the ldap connection to $binddn 
my $result = $ldap->bind($settings{'binddn'}, password => $password);
die $result->error() if $result->code();

# Search for sambaSamAccount below ou=People,dc=skole,dc=skolelinux,dc=no
my $msg = $ldap->search(base   => "dc=domain,dc=com",
                        scope  => "sub",
                        filter => "(&(objectClass=shadowAccount)(objectClass=inetOrgPerson)(objectClass=posixAccount))",
                        attrs =>  [ 'shadowFlag', 'shadowMin', 'shadowMax', 'shadowWarning', 'shadowInactive', 'shadowLastChange', 'shadowExpire',
                                    'uid', 'hAccountInitialSetup', 'hAccountSetupDate', 'SelfServiceLastPasswordChange'  ]
);

# If nothing found print a message and exit
if (!$msg->count > 0) {
        print(STDERR "[$0]: ERROR: no results found in ldap, exiting.\n");
        return 0;
}

# Go through the subtree and add missing attributes
foreach my $entry ($msg->all_entries()) {

        $users_total++;
        my %ldap = ();  # empty array

        if (!defined($entry->get_value("shadowFlag"))) {
                print "\tAdding 'shadowFlag 0' for user '" . $entry->get_value("uid") . "'\n";
                $entry->add(shadowFlag => "0");
                $users_mod++;
        }

        if (!defined($entry->get_value("shadowMin"))) {
                print "\tAdding 'shadowMin 0' for user '" . $entry->get_value("uid") . "'\n";
                $entry->add(shadowMin => "0");
        }

        if (!defined($entry->get_value("shadowMax"))) {
                print "\tAdding 'shadowMax 180' for user '" . $entry->get_value("uid") . "'\n";
                $entry->add(shadowMax => "180");
        }

        if (!defined($entry->get_value("shadowWarning"))) {
                print "\tAdding 'shadowWarning 10' for user '" . $entry->get_value("uid") . "'\n";
                $entry->add(shadowWarning => "10");
        }

        if (!defined($entry->get_value("shadowInactive"))) {
                print "\tAdding 'shadowInactive -1' for user '" . $entry->get_value("uid") . "'\n";
                $entry->add(shadowInactive => "-1");
        }

        # hAccountInitialSetup
        if (!defined($entry->get_value("hAccountInitialSetup"))) {
                print "\tAdding 'hAccountInitialSetup 0' for user '" . $entry->get_value("uid") . "'\n";
                $entry->add(hAccountInitialSetup => "0");
        }

        # hAccountSetupDate
        if (!defined($entry->get_value("hAccountSetupDate"))) {
                print "\tAdding 'hAccountSetupDate' for user '" . $entry->get_value("uid") . "'\n";
                $entry->add(hAccountSetupDate => "20150101");

        }

        # SelfServiceLastPasswordChange (20131023) sync date to shadowLastChange days (14883)
        if (!defined($entry->get_value("SelfServiceLastPasswordChange"))) {
                print "\tAdding 'SelfServiceLastPasswordChange' for user '" . $entry->get_value("uid") . "'\n";
                $entry->add(SelfServiceLastPasswordChange => "20150101");

        } else {
                ( $ldap{'year'}, $ldap{'month'}, $ldap{'day'} ) = ($entry->get_value("SelfServiceLastPasswordChange") =~ m{(\d\d\d\d)(\d\d)(\d\d)});  # split into (2013)(10)(23)
                $ldap{'now'}  = DateToSeconds($ldap{'day'}, $ldap{'month'}, $ldap{'year'});
                #my $datediff     = int(($today{'now'} - $ldap{'now'})/86400);
                $ldap{'days_since_epoch'} = int( $ldap{'now'} / 86400 );
        }
        if (!defined($entry->get_value("shadowLastChange"))) {
                print "\tAdding 'shadowLastChange " . $ldap{'days_since_epoch'} . "' for user '" . $entry->get_value("uid") . "'\n";
                $entry->add(shadowLastChange => $ldap{'days_since_epoch'});
        }

        #shadowExpire
        if (!defined($entry->get_value("shadowExpire"))) {
                $today{'days_since_epoch'} = int ( $today{'now'} / 86400 );
                print "NOW = " . $today{'days_since_epoch'} . "\n";
                $ldap{'shadowExpire'} = $today{'days_since_epoch'} + 180 + &rand_range (1,45);
                print "\tAdding 'shadowExpire " . $ldap{'shadowExpire'} . "' for user '" . $entry->get_value("uid") . "'\n";
                $entry->add(shadowExpire => $ldap{'shadowExpire'});
        }

        # Commit to ldap tree and check for errors
        $result = $entry->update($ldap);

        if ($result->code()) {
                print "********* Failed to update ldap for user '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . $result->error() ."\n\n";
        } else {
                print "Updated ldap for user '" . $entry->get_value("uid") . "' DN=" . $entry->dn() . " sucessfuly\n\n";
        }
}

$msg = $ldap->unbind;

print "Total:$users_total Mod:$users_mod\n";

