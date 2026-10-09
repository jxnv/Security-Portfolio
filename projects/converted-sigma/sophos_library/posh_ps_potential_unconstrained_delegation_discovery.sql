-- Title: Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock
-- ID: cdfa73b6-3c9d-4bb8-97f8-ddbd8921f5c5
-- Status: experimental
-- Level: medium
-- Author: frack113
-- Date: 2025-03-05
-- Tags: attack.reconnaissance, attack.discovery, attack.credential-access, attack.t1018, attack.t1558, attack.t1589.002
-- Description: Detects the use of the "Get-ADComputer" cmdlet in order to identify systems which are configured for unconstrained delegation.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ScriptBlockText ILIKE '%-Properties*TrustedForDelegation%' OR ScriptBlockText ILIKE '%-Properties*TrustedToAuthForDelegation%' OR ScriptBlockText ILIKE '%-Properties*msDS-AllowedToDelegateTo%' OR ScriptBlockText ILIKE '%-Properties*PrincipalsAllowedToDelegateToAccount%' OR ScriptBlockText ILIKE '%-LDAPFilter*(userAccountControl:1.2.840.113556.1.4.803:=524288)%'))
