// Title: Suspicious Download from Office Domain
// ID: 00d49ed5-4491-4271-a8db-650a4ef6f8c1
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-12-27
// Tags: attack.command-and-control, attack.resource-development, attack.t1105, attack.t1608
// Description: Detects suspicious ways to download files from Microsoft domains that are used to store attachments in Emails or OneNote documents
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*https://attachment.outlook.live.net/owa/*" OR CommandLine: "*https://onenoteonlinesync.onenote.com/onenoteonlinesync/*")) AND (((Image="*\\curl.exe" OR Image="*\\wget.exe")) OR ((CommandLine: "*Invoke-WebRequest*" OR CommandLine: "*iwr *" OR CommandLine: "*curl *" OR CommandLine: "*wget *" OR CommandLine: "*Start-BitsTransfer*" OR CommandLine: "*.DownloadFile(*" OR CommandLine: "*.DownloadString(*"))))
