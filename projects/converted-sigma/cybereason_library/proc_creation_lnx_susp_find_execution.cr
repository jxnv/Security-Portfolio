// Title: Potential Discovery Activity Using Find - Linux
// ID: 8344c0e5-5783-47cc-9cf9-a0f7fd03e6cf
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-28
// Tags: attack.discovery, attack.t1083
// Description: Detects usage of "find" binary in a suspicious manner to perform discovery
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*/find" AND (CommandLine contains "-perm -4000" OR CommandLine contains "-perm -2000" OR CommandLine contains "-perm 0777" OR CommandLine contains "-perm -222" OR CommandLine contains "-perm -o w" OR CommandLine contains "-perm -o x" OR CommandLine contains "-perm -u=s" OR CommandLine contains "-perm -g=s"))
