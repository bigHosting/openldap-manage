#!/usr/bin/perl

#use strict;
#use warnings;

use POSIX qw(strftime);
use File::Basename;
use Getopt::Long;
use Net::LDAPS;
use Term::ReadKey;
use Sys::Hostname;

my %settings = (
       'binddn' ,      'uid=umsrvcron.sec.domain.com,ou=applications,o=Domain,dc=domain,dc=com',
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

my $password = &get_password();

my $ldap = Net::LDAPS->new(
         hostname,
         verify  => "none",
         onerror => 'warn',
         port    => $settings{'ldap_port'},
         version => $settings{'ldap_version'},
         debug   => $settings{'ldap_debug'},
         timeout => $settings{'ldap_timeout'},
) or die "Can not connect ldap: $@";

my $mesg = $ldap->bind($settings{'binddn'}, password => $password);


$mesg = $ldap->bind ;

if ($ARGV[0] eq ""){
        print "Ussage: search uid";
}
else {
 	$filter = "uid=$ARGV[0]*";
}

$mesg = $ldap->search( filter=>$filter, base=>"ou=users,o=Domain,dc=domain,dc=com", attrs=> ['cn', 'uid', 'uidNumber', 'gidNumber', 'shadowExpire', 'mail', 'l', 'mobile', 'loginShell', 'host']);

@entries = $mesg->entries;

if ( @entries == 0 ) {
	print "There were no users found!\n";
}
else {
	print "Found " . @entries . " users\n";
	
	foreach $entry (@entries) {
		print "dn: " . $entry->dn() . "\n";
		@attrs = $entry->attributes();
		foreach $attr (@attrs) {
			printf("\t%s: %s\n", $attr, $entry->get_value($attr));
		}
	}
}

$mesg = $ldap->unbind;
