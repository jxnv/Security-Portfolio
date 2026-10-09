// Title: Suspicious Machine Account Replication - DcSync Indicator
// ID: 611eab06-a145-4dfa-a295-3ccc5c20f59a
// Status: test
// Level: medium
// Author: Benjamin Delpy, Florian Roth (Nextron Systems), Scott Dermett, Sorina Ionescu
// Date: 2018-06-03
// Tags: attack.credential-access, attack.s0002, attack.t1003.006, cve.2026-54121
// Description: Detects suspicious Active Directory Replication Service (ADRS) requests originating from
// a machine account (SubjectUserName ending in '$') rather than a legitimate Domain Controller.
// 
// Under normal operation, only Domain Controllers initiate replication requests carrying the
// DS-Replication-Get-Changes-All right. If a threat actor obtains valid machine account
// credentials — for example by abusing certificate-based authentication (PKINIT) to
// impersonate a DC after exploiting a CA vulnerability such as CVE-2026-54121 (Certighost),
// where a temporary machine account is created to request a DC certificate and then used to
// perform DCSync — they can dump all domain credential material including the krbtgt hash.
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID: "4662" AND (Properties: "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties: "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties: "*9923a32a-3607-11d2-b9be-0000f87a36b2*" OR Properties: "*89e95b76-444d-4c62-991a-0facbeda640c*") AND SubjectUserName="*$") AND NOT ((SubjectUserSid="S-1-5-18*")))
