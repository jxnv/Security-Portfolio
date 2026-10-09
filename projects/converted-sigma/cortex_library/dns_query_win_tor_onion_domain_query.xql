// Title: DNS Query Tor .Onion Address - Sysmon
// ID: b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544
// Status: test
// Level: high
// Author: frack113
// Date: 2022-02-20
// Tags: attack.command-and-control, attack.t1090.003
// Description: Detects DNS queries to an ".onion" address related to Tor routing networks
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((QueryName endswith ".hiddenservice.net" or QueryName endswith ".onion.ca" or QueryName endswith ".onion.cab" or QueryName endswith ".onion.casa" or QueryName endswith ".onion.city" or QueryName endswith ".onion.direct" or QueryName endswith ".onion.dog" or QueryName endswith ".onion.glass" or QueryName endswith ".onion.gq" or QueryName endswith ".onion.ink" or QueryName endswith ".onion.it" or QueryName endswith ".onion.link" or QueryName endswith ".onion.lt" or QueryName endswith ".onion.lu" or QueryName endswith ".onion.nu" or QueryName endswith ".onion.pet" or QueryName endswith ".onion.plus" or QueryName endswith ".onion.rip" or QueryName endswith ".onion.sh" or QueryName endswith ".onion.to" or QueryName endswith ".onion.top" or QueryName endswith ".onion" or QueryName endswith ".s1.tor-gateways.de" or QueryName endswith ".s2.tor-gateways.de" or QueryName endswith ".s3.tor-gateways.de" or QueryName endswith ".s4.tor-gateways.de" or QueryName endswith ".s5.tor-gateways.de" or QueryName endswith ".t2w.pw" or QueryName endswith ".tor2web.ae.org" or QueryName endswith ".tor2web.blutmagie.de" or QueryName endswith ".tor2web.com" or QueryName endswith ".tor2web.fi" or QueryName endswith ".tor2web.io" or QueryName endswith ".tor2web.org" or QueryName endswith ".tor2web.xyz" or QueryName endswith ".torlink.co"))
