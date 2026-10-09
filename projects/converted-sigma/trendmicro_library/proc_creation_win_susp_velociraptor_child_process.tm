// Title: Suspicious Velociraptor Child Process
// ID: 4bc90587-e6ca-4b41-be0b-ed4d04e4ed0c
// Status: experimental
// Level: high
// Author: Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-08-29
// Tags: attack.command-and-control, attack.persistence, attack.t1219
// Description: Detects the suspicious use of the Velociraptor DFIR tool to execute other tools or download additional payloads, as seen in a campaign where it was abused for remote access and to stage further attacks.
// Converted by: Sigma Universal SIEM/EDR CLI

((ParentImage="*\\Velociraptor.exe") AND (((CommandLine: "*msiexec*" AND CommandLine: "*/i*" AND CommandLine: "*http*")) OR ((Image="*\\powershell.exe" OR Image="*\\powershell_ise.exe" OR Image="*\\pwsh.exe") AND (CommandLine: "*Invoke-WebRequest *" OR CommandLine: "*IWR *" OR CommandLine: "*.DownloadFile*" OR CommandLine: "*.DownloadString*")) OR ((CommandLine: "*code.exe*" AND CommandLine: "*tunnel*" AND CommandLine: "*--accept-server-license-terms*"))))
