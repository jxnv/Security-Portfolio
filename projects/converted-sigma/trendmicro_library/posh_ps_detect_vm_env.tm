// Title: Powershell Detect Virtualization Environment
// ID: d93129cd-1ee0-479f-bc03-ca6f129882e3
// Status: test
// Level: medium
// Author: frack113, Duc.Le-GTSC
// Date: 2021-08-03
// Tags: attack.discovery, attack.stealth, attack.t1497.001
// Description: Adversaries may employ various system checks to detect and avoid virtualization and analysis environments.
// This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox
// Converted by: Sigma Universal SIEM/EDR CLI

(((ScriptBlockText: "*Get-WmiObject*" OR ScriptBlockText: "*gwmi*")) AND ((ScriptBlockText: "*MSAcpi_ThermalZoneTemperature*" OR ScriptBlockText: "*Win32_ComputerSystem*")))
