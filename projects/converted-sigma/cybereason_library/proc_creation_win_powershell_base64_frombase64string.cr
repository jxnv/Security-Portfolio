// Title: PowerShell Base64 Encoded FromBase64String Cmdlet
// ID: fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2019-08-24
// Tags: attack.stealth, attack.t1140, attack.execution, attack.t1059.001
// Description: Detects usage of a base64 encoded "FromBase64String" cmdlet in a process command line
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "OjpGcm9tQmFzZTY0U3RyaW5n" OR CommandLine contains "o6RnJvbUJhc2U2NFN0cmluZ" OR CommandLine contains "6OkZyb21CYXNlNjRTdHJpbm")) OR ((CommandLine contains "OgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA" OR CommandLine contains "oAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnA" OR CommandLine contains "6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZw")))
