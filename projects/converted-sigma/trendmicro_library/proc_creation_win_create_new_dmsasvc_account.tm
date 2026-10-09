// Title: New DMSA Service Account Created in Specific OUs
// ID: 0ea8db81-2ff6-4525-9448-33bbe7effc13
// Status: experimental
// Level: medium
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-05-24
// Tags: attack.privilege-escalation, attack.initial-access, attack.persistence, attack.stealth, attack.t1078.002, attack.t1098
// Description: Detects the creation of a dMSASvc account using the New-ADServiceAccount cmdlet in certain OUs.
// The fact that the Cmdlet is used to create a dMSASvc account in a specific OU is highly suspicious.
// It is a pattern trying to exploit the BadSuccessor privilege escalation vulnerability in Windows Server 2025.
// On top of that, if the user that is creating the dMSASvc account is not a legitimate administrator or does not have the necessary permissions,
// it is a strong signal of an attempted or successful abuse of the BaDSuccessor vulnerability for privilege escalation within the Windows Server 2025 Active Directory environment.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*New-ADServiceAccount*" AND CommandLine: "*-CreateDelegatedServiceAccount*" AND CommandLine: "*-path*")) AND (((Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\powershell_ise.exe")) OR ((OriginalFileName: "powershell.exe" OR OriginalFileName: "pwsh.dll" OR OriginalFileName: "powershell_ise.exe"))))
