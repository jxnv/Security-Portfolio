// Title: Binary Padding - MacOS
// ID: 95361ce5-c891-4b0a-87ca-e24607884a96
// Status: test
// Level: high
// Author: Igor Fits, Mikhail Larin, oscd.community
// Date: 2020-10-19
// Tags: attack.stealth, attack.t1027.001
// Description: Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This rule detect using dd and truncate to add a junk data to file.
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*/dd" AND (CommandLine contains "if=/dev/zero" OR CommandLine contains "if=/dev/random" OR CommandLine contains "if=/dev/urandom")) OR (Image="*/truncate" AND CommandLine contains "-s +"))
