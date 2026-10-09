// Title: LSASS Memory Access by Tool With Dump Keyword In Name
// ID: 9bd012ee-0dff-44d7-84a0-aa698cfd87a3
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-02-10
// Tags: attack.credential-access, attack.t1003.001, attack.s0002
// Description: Detects LSASS process access requests from a source process with the "dump" keyword in its image name.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetImage endswith "\\lsass.exe" and SourceImage contains "dump" and (GrantedAccess endswith "10" or GrantedAccess endswith "30" or GrantedAccess endswith "50" or GrantedAccess endswith "70" or GrantedAccess endswith "90" or GrantedAccess endswith "B0" or GrantedAccess endswith "D0" or GrantedAccess endswith "F0" or GrantedAccess endswith "18" or GrantedAccess endswith "38" or GrantedAccess endswith "58" or GrantedAccess endswith "78" or GrantedAccess endswith "98" or GrantedAccess endswith "B8" or GrantedAccess endswith "D8" or GrantedAccess endswith "F8" or GrantedAccess endswith "1A" or GrantedAccess endswith "3A" or GrantedAccess endswith "5A" or GrantedAccess endswith "7A" or GrantedAccess endswith "9A" or GrantedAccess endswith "BA" or GrantedAccess endswith "DA" or GrantedAccess endswith "FA" or GrantedAccess endswith "0x14C2" or GrantedAccess endswith "FF"))
