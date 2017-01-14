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

sub get_password {
        print "Enter " . $settings{'binddn'} . "'s password: ";
        ReadMode('noecho');
        my $pass = ReadLine(0);
        chomp $pass;
        ReadMode(0);
        print "\n";
        return ($pass);
}

$settings{'host'} = hostname;

my @attrs_shadow = [ 'shadowFlag', 'shadowLastChange', 'shadowMax', 'shadowMin', 'shadowWarning', 'shadowExpire', 'shadowInactive' ];


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
                        filter => "(&(objectClass=shadowAccount)(objectClass=inetOrgPerson))"
);

# If nothing found print a message and exit
if (!$msg->count > 0) {
        print(STDERR "[$0]: ERROR: No user accounts found in ldap, exiting.\n");
        return 0;
}

# Go through the subtree and add missing attributes
foreach my $entry ($msg->all_entries()) {

        my @attrs_shadow = $entry->attributes();

        foreach my $attribute (@attrs_shadow) {
                if (!defined($entry->get_value($attribute))) {
                        print "\t" . $attribute . "*** : " . $entry->dn() . "***\n";
                        $users_total++;
                }
        }

}

$msg = $ldap->unbind;

print "Total of $users_total attribute updates needed\n";

