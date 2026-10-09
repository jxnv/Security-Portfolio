// Title: Potential Data Exfiltration Via Audio File
// ID: e4f93c99-396f-47c8-bb0f-201b1fa69034
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-16
// Tags: attack.exfiltration
// Description: Detects potential exfiltration attempt via audio file using PowerShell
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ScriptBlockText contains "[System.Math]::" and ScriptBlockText contains "[IO.FileMode]::" and ScriptBlockText contains "BinaryWriter")) and ((ScriptBlockText contains "0x52" and ScriptBlockText contains "0x49" and ScriptBlockText contains "0x46" and ScriptBlockText contains "0x57" and ScriptBlockText contains "0x41" and ScriptBlockText contains "0x56" and ScriptBlockText contains "0x45" and ScriptBlockText contains "0xAC")))
