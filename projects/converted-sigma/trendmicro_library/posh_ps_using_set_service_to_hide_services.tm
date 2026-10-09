// Title: Abuse of Service Permissions to Hide Services Via Set-Service - PS
// ID: 953945c5-22fe-4a92-9f8a-a9edc1e522da
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-17
// Tags: attack.persistence, attack.privilege-escalation, attack.execution, attack.stealth, attack.t1574.011
// Description: Detects usage of the "Set-Service" powershell cmdlet to configure a new SecurityDescriptor that allows a service to be hidden from other utilities such as "sc.exe", "Get-Service"...etc. (Works only in powershell 7)
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText: "*Set-Service *" AND ScriptBlockText: "*DCLCWPDTSD*") AND (ScriptBlockText: "*-SecurityDescriptorSddl *" OR ScriptBlockText: "*-sd *"))
