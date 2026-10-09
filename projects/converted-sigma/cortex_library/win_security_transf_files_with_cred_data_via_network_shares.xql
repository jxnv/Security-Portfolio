// Title: Transferring Files with Credential Data via Network Shares
// ID: 910ab938-668b-401b-b08c-b596e80fdca5
// Status: test
// Level: medium
// Author: Teymur Kheirkhabarov, oscd.community
// Date: 2019-10-22
// Tags: attack.credential-access, attack.t1003.002, attack.t1003.001, attack.t1003.003
// Description: Transferring files with well-known filenames (sensitive files with credential data) using network shares
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 5145) and (((RelativeTargetName contains "\\mimidrv" or RelativeTargetName contains "\\lsass" or RelativeTargetName contains "\\windows\\minidump\\" or RelativeTargetName contains "\\hiberfil" or RelativeTargetName contains "\\sqldmpr")) or ((RelativeTargetName = "Windows\\NTDS\\ntds.dit" or RelativeTargetName = "Windows\\System32\\config\\SAM" or RelativeTargetName = "Windows\\System32\\config\\SECURITY" or RelativeTargetName = "Windows\\System32\\config\\SYSTEM"))))
