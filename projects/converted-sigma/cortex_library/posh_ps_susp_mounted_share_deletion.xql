// Title: PowerShell Deleted Mounted Share
// ID: 66a4d409-451b-4151-94f4-a55d559c49b0
// Status: test
// Level: medium
// Author: oscd.community, @redcanary, Zach Stanford @svch0st
// Date: 2020-10-08
// Tags: attack.stealth, attack.t1070.005
// Description: Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ScriptBlockText contains "Remove-SmbShare" or ScriptBlockText contains "Remove-FileShare")) and not (((ScriptBlockText contains "FileShare.cdxml" and ScriptBlockText contains "Microsoft.PowerShell.Core\\Export-ModuleMember" and ScriptBlockText contains "ROOT/Microsoft/Windows/Storage/MSFT_FileShare" and ScriptBlockText contains "ObjectModelWrapper" and ScriptBlockText contains "Cmdletization.MethodParameter"))))
