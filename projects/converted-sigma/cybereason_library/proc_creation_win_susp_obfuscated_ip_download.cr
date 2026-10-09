// Title: Obfuscated IP Download Activity
// ID: cb5a2333-56cf-4562-8fcb-22ba1bca728d
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), X__Junior (Nextron Systems)
// Date: 2022-08-03
// Tags: attack.discovery
// Description: Detects use of an encoded/obfuscated version of an IP address (hex, octal...) in an URL combined with a download command
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "Invoke-WebRequest" OR CommandLine contains "iwr " OR CommandLine contains "Invoke-RestMethod" OR CommandLine contains "irm " OR CommandLine contains "wget " OR CommandLine contains "curl " OR CommandLine contains "DownloadFile" OR CommandLine contains "DownloadString")) AND (((CommandLine contains " 0x" OR CommandLine contains "//0x" OR CommandLine contains ".0x" OR CommandLine contains ".00x")) OR ((CommandLine contains "http://%" AND CommandLine contains "%2e")) OR ((CommandLine=regex("https?://[0-9]{1,3}\\.[0-9]{1,3}\\.0[0-9]{3,4}")) OR (CommandLine=regex("https?://[0-9]{1,3}\\.0[0-9]{3,7}")) OR (CommandLine=regex("https?://0[0-9]{3,11}")) OR (CommandLine=regex("https?://(?:0[0-9]{1,11}\\.){3}0[0-9]{1,11}")) OR (CommandLine=regex("https?://0[0-9]{1,11}")) OR (CommandLine=regex(" [0-7]{7,13}")))) AND NOT ((CommandLine=regex("https?://(?:(?:25[0-5]|(?:2[0-4]|1\\d|[1-9])?\\d)(?:\\.|\\b)){4}"))))
