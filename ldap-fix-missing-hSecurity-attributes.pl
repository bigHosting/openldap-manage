#!/usr/bin/perl

use strict;
use warnings;

use Net::LDAP;
use Net::LDAPS;
use Term::ReadKey;
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

sub get_password {
        print "Enter " . $settings{'binddn'} . "'s password: ";
        ReadMode('noecho');
        my $pass = ReadLine(0);
        chomp $pass;
        ReadMode(0);
        print "\n";
        return ($pass);
}

my $password = &get_password();

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

# Search for accounts with objectClass hSecurity
my $msg = $ldap->search(base   => "dc=domain,dc=com",
                        scope  => "sub",
                        filter => "(&(objectClass=shadowAccount)(objectClass=inetOrgPerson)(objectClass=hSecurity))",
                        attrs =>  [ 'uid','hAccountInitialSetup','hAccountSetupDate','hAllowPasswordChange','hEnablePasswordChange','hEnablePasswordLock','hPasswordSecretA','hPasswordSecretB',
                                    'hPasswordTries', 'SelfServiceAccountLocked','SelfServiceLastPasswordChange','SelfServiceSentEmail' ]
);

# If nothing found print a message and exit
if (!$msg->count > 0) {
        print(STDERR "[$0]: ERROR: No user accounts found in ldap, exiting.\n");
        return 0;
}

# Go through the subtree and add missing attributes
foreach my $entry ($msg->all_entries()) {

        my $needs_update = 0;

        if (!defined($entry->get_value("hStatus"))) {
                print "\thStatus *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
                $entry->add(hStatus => "1");
                $needs_update++;
        }

        if (!defined($entry->get_value("hAccountInitialSetup"))) {
                print "\tAdding hAccountInitialSetup *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
                $entry->add(hAccountInitialSetup => "0");
                $needs_update++;
        }
        if (!defined($entry->get_value("hAccountSetupDate"))) {
                print "\thAccountSetupDate *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
                $entry->add(hAccountSetupDate => "20131106");
                $needs_update++;
        }
# to be removed from schema
#        if (!defined($entry->get_value("hAllowPasswordChange"))) {
#                print "\thAllowPasswordChange *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
#                $entry->add(hAllowPasswordChange => "1");
#                $needs_update++;
#        }
#        if (!defined($entry->get_value("hEnablePasswordChange"))) {
#                print "\thEnablePasswordChange *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
#                $entry->add(hEnablePasswordChange => "1");
#                $needs_update++;
#        }
#        if (!defined($entry->get_value("hEnablePasswordLock"))) {
#                print "\thEnablePasswordLock *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
#                $entry->add(hEnablePasswordLock => "0");
#                $needs_update++;
#        }
        if (!defined($entry->get_value("hPasswordSecretA"))) {
                print "\thPasswordSecretA *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
                $entry->add(hPasswordSecretA => "NOTSETUP");
                $needs_update++;
        }
        if (!defined($entry->get_value("hPasswordSecretB"))) {
                print "\thPasswordSecretB *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
                $entry->add(hPasswordSecretB => "NOTSETUP");
                $needs_update++;
        }
#        if (!defined($entry->get_value("hPasswordTries"))) {
#                print "\thPasswordTries *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
#                $entry->add(hPasswordTries => "0");
#                $needs_update++;
#        }
# to be removed from schema
#        if (!defined($entry->get_value("SelfServiceAccountLocked"))) {
#                print "\thSelfServiceAccountLocked *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
#                $entry->add(SelfServiceAccountLocked => "0");
#                $needs_update++;
#        }
        if (!defined($entry->get_value("SelfServiceLastPasswordChange"))) {
                print "\tSelfServiceLastPasswordChange *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
                $entry->add(SelfServiceLastPasswordChange => "20131106");
                $needs_update++;
        }
# to be removed from schema
#        if (!defined($entry->get_value("SelfServiceSentEmail"))) {
#                print "\tSelfServiceSentEmail *** '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . "***\n";
#                $entry->add(SelfServiceSentEmail => "0");
#                $needs_update++;
#        }

        if ($needs_update != 0) {
                # Commit to ldap tree and check for errors
                $result = $entry->update($ldap);

                if ($result->code()) {
                        print "********* Failed to update ldap for user '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . $result->error() ."\n\n";
                } else {
                        print "Updated ldap for user '" . $entry->get_value("uid") . "' DN=" . $entry->dn() . " sucessfuly\n\n";
                }
        }

}

$msg = $ldap->unbind;


