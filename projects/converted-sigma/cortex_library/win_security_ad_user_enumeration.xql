// Title: Potential AD User Enumeration From Non-Machine Account
// ID: ab6bffca-beff-4baa-af11-6733f296d57a
// Status: test
// Level: medium
// Author: Maxime Thiebaut (@0xThiebaut)
// Date: 2020-03-30
// Tags: attack.discovery, attack.t1087.002
// Description: Detects read access to a domain user from a non-machine account
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 4662 and ObjectType contains "bf967aba-0de6-11d0-a285-00aa003049e2" and (AccessMask endswith "1?" or AccessMask endswith "3?" or AccessMask endswith "4?" or AccessMask endswith "7?" or AccessMask endswith "9?" or AccessMask endswith "B?" or AccessMask endswith "D?" or AccessMask endswith "F?")) and not (((SubjectUserName endswith "$") or (SubjectUserName startswith "MSOL_"))))
