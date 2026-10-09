-- Title: Potential Kerberos Coercion by Spoofing SPNs via DNS Manipulation
-- ID: b07e58cf-cacc-4135-8473-ccb2eba63dd2
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-06-20
-- Tags: attack.collection, attack.credential-access, attack.t1557.003, attack.persistence, attack.privilege-escalation
-- Description: Detects modifications to DNS records in Active Directory where the Distinguished Name (DN) contains a base64-encoded blob
-- matching the pattern "1UWhRCAAAAA...BAAAA". This pattern corresponds to a marshaled CREDENTIAL_TARGET_INFORMATION structure,
-- commonly used in Kerberos coercion attacks. Adversaries may exploit this to coerce victim systems into authenticating to
-- attacker-controlled hosts by spoofing SPNs via DNS. It is one of the strong indicators of a Kerberos coercion attack,.
-- where adversaries manipulate DNS records to spoof Service Principal Names (SPNs) and redirect authentication requests like CVE-2025-33073.
-- Please investigate the user account that made the changes, as it is likely a low-privileged account that has been compromised.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((EventID = '4662' AND (AdditionalInfo LIKE '%UWhRCA%' AND AdditionalInfo LIKE '%BAAAA%' AND AdditionalInfo LIKE '%CN=MicrosoftDNS%')) OR ((EventID = '5136' OR EventID = '5137') AND ObjectClass = 'dnsNode' AND (ObjectDN LIKE '%UWhRCA%' AND ObjectDN LIKE '%BAAAA%' AND ObjectDN LIKE '%CN=MicrosoftDNS%')))
