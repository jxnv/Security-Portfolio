// Title: Invoke-Obfuscation Via Stdin - PowerShell Module
// ID: c72aca44-8d52-45ad-8f81-f96c4d3c755e
// Status: test
// Level: high
// Author: Nikita Nazarov, oscd.community
// Date: 2020-10-12
// Tags: attack.stealth, attack.t1027, attack.execution, attack.t1059.001
// Description: Detects Obfuscated Powershell via Stdin in Scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (Payload ~= "(?i)(set).*&&\\s?set.*(environment|invoke|\\$?\\{?input).*&&.*\"")
