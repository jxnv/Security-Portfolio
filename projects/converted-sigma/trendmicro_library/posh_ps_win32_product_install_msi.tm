// Title: PowerShell WMI Win32_Product Install MSI
// ID: 91109523-17f0-4248-a800-f81d9e7c081d
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-04-24
// Tags: attack.stealth, attack.t1218.007
// Description: Detects the execution of an MSI file using PowerShell and the WMI Win32_Product class
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText: "*Invoke-CimMethod *" AND ScriptBlockText: "*-ClassName *" AND ScriptBlockText: "*Win32_Product *" AND ScriptBlockText: "*-MethodName *" AND ScriptBlockText: "*.msi*"))
