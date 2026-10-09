// Title: Suspicious FromBase64String Usage On Gzip Archive - Ps Script
// ID: df69cb1d-b891-4cd9-90c7-d617d90100ce
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-12-23
// Tags: attack.command-and-control, attack.t1132.001
// Description: Detects attempts of decoding a base64 Gzip archive in a PowerShell script. This technique is often used as a method to load malicious content into memory afterward.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((ScriptBlockText contains "FromBase64String" and ScriptBlockText contains "MemoryStream" and ScriptBlockText contains "H4sI"))
