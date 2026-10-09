// Title: Potential Privilege Escalation via Local Kerberos Relay over LDAP
// ID: 749c9f5e-b353-4b90-a9c1-05243357ca4b
// Status: test
// Level: high
// Author: Elastic, @SBousseaden
// Date: 2022-04-27
// Tags: attack.privilege-escalation, attack.credential-access, attack.t1548
// Description: Detects a suspicious local successful logon event where the Logon Package is Kerberos, the remote address is set to localhost, and the target user SID is the built-in local Administrator account.
// This may indicate an attempt to leverage a Kerberos relay attack variant that can be used to elevate privilege locally from a domain joined limited user to local System privileges.
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID: "4624" AND LogonType: "3" AND AuthenticationPackageName: "Kerberos" AND IpAddress: "127.0.0.1" AND TargetUserSid="S-1-5-21-*" AND TargetUserSid="*-500") AND NOT ((IpPort: "0")))
