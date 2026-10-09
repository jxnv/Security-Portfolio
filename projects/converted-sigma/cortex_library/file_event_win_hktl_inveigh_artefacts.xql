// Title: HackTool - Inveigh Execution Artefacts
// ID: bb09dd3e-2b78-4819-8e35-a7c1b874e449
// Status: test
// Level: critical
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-24
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects the presence and execution of Inveigh via dropped artefacts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path endswith "\\Inveigh-Log.txt" or action_file_path endswith "\\Inveigh-Cleartext.txt" or action_file_path endswith "\\Inveigh-NTLMv1Users.txt" or action_file_path endswith "\\Inveigh-NTLMv2Users.txt" or action_file_path endswith "\\Inveigh-NTLMv1.txt" or action_file_path endswith "\\Inveigh-NTLMv2.txt" or action_file_path endswith "\\Inveigh-FormInput.txt" or action_file_path endswith "\\Inveigh.dll" or action_file_path endswith "\\Inveigh.exe" or action_file_path endswith "\\Inveigh.ps1" or action_file_path endswith "\\Inveigh-Relay.ps1"))
