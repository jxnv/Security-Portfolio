// Title: Potential Persistence Via TypedPaths
// ID: 086ae989-9ca6-4fe7-895a-759c5544f247
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-22
// Tags: attack.persistence
// Description: Detects modification addition to the 'TypedPaths' key in the user or admin registry from a non standard application. Which might indicate persistence attempt
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject: "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths\\*") AND NOT (((Image: "C:\\Windows\\explorer.exe" OR Image: "C:\\Windows\\SysWOW64\\explorer.exe"))))
