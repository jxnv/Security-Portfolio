// Title: Remove Immutable File Attribute
// ID: 34979410-e4b5-4e5d-8cfb-389fdff05c12
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-15
// Tags: attack.defense-impairment, attack.t1222.002
// Description: Detects usage of the 'chattr' utility to remove immutable file attribute.
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*/chattr" AND CommandLine: "* -i *")
