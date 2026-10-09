// Title: Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock
// ID: cdfa73b6-3c9d-4bb8-97f8-ddbd8921f5c5
// Status: experimental
// Level: medium
// Author: frack113
// Date: 2025-03-05
// Tags: attack.reconnaissance, attack.discovery, attack.credential-access, attack.t1018, attack.t1558, attack.t1589.002
// Description: Detects the use of the "Get-ADComputer" cmdlet in order to identify systems which are configured for unconstrained delegation.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "-Properties*TrustedForDelegation" or ScriptBlockText contains "-Properties*TrustedToAuthForDelegation" or ScriptBlockText contains "-Properties*msDS-AllowedToDelegateTo" or ScriptBlockText contains "-Properties*PrincipalsAllowedToDelegateToAccount" or ScriptBlockText contains "-LDAPFilter*(userAccountControl:1.2.840.113556.1.4.803:=524288)"))
