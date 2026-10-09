// Title: AppX Located in Known Staging Directory Added to Deployment Pipeline
// ID: 5cdeaf3d-1489-477c-95ab-c318559fc051
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-01-11
// Tags: attack.stealth
// Description: Detects an appx package that was added to the pipeline of the "to be processed" packages that is located in a known folder often used as a staging directory.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 854) and (((Path contains ":\\PerfLogs\\" or Path contains ":\\Users\\Public\\" or Path contains ":\\Windows\\Temp\\" or Path contains "\\AppdData\\Local\\Temp\\" or Path contains "\\Desktop\\" or Path contains "\\Downloads\\")) or ((Path contains ":/Perflogs/" or Path contains ":/Users/Public/" or Path contains ":/Windows/Temp/" or Path contains "/AppdData/Local/Temp/" or Path contains "/Desktop/" or Path contains "/Downloads/"))))
