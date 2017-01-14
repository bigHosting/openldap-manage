#!/usr/bin/perl -w

use strict;
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
my $users_total = 0;

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
                        filter => "(&(objectClass=shadowAccount)(objectClass=inetOrgPerson)(!(objectClass=hSecurity)))");

# If nothing found print a message and exit
if (!$msg->count > 0) {
        print(STDERR "[$0]: All accounts have objectClass=hSecurity.\n");
        return 0;
}

# Go through the subtree and add missing attributes
foreach my $entry ($msg->all_entries()) {

        print "\tAdding 'objectClass=hSecurity' for user '" . $entry->get_value("uid") . "'\n";
        $entry->add(objectClass => "hSecurity");

        # Commit to ldap tree and check for errors
        $result = $entry->update($ldap);

        if ($result->code()) {
                print "********* Failed to update ldap for user '" . $entry->get_value("uid") . "': " . $entry->dn() . ": " . $result->error() ."\n\n";
        } else {
                print "Updated ldap for user '" . $entry->get_value("uid") . "' DN=" . $entry->dn() . " sucessfuly\n\n";
                $users_total++;
        }


}

$msg = $ldap->unbind;

print "Total:$users_total\n";

