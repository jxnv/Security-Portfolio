// Title: Powershell Store File In Alternate Data Stream
// ID: a699b30e-d010-46c8-bbd1-ee2e26765fe9
// Status: test
// Level: medium
// Author: frack113
// Date: 2021-09-02
// Tags: attack.stealth, attack.t1564.004
// Description: Storing files in Alternate Data Stream (ADS) similar to Astaroth malware.
// Converted by: Sigma Universal SIEM/EDR CLI

((ScriptBlockText contains "Start-Process" AND ScriptBlockText contains "-FilePath \"$env:comspec\" " AND ScriptBlockText contains "-ArgumentList " AND ScriptBlockText contains ">"))
