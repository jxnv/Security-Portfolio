// Title: Important Windows Service Terminated With Error
// ID: d6b5520d-3934-48b4-928c-2aa3f92d6963
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-04-14
// Tags: attack.stealth
// Description: Detects important or interesting Windows services that got terminated for whatever reason
// Converted by: Sigma Universal SIEM/EDR CLI

((Provider_Name == "Service Control Manager" AND EventID == "7023") AND (((param1 contains " Antivirus" OR param1 contains " Firewall" OR param1 contains "Application Guard" OR param1 contains "BitLocker Drive Encryption Service" OR param1 contains "Encrypting File System" OR param1 contains "Microsoft Defender" OR param1 contains "Threat Protection" OR param1 contains "Windows Event Log")) OR ((Binary contains "770069006e0064006500660065006e006400" OR Binary contains "4500760065006e0074004c006f006700" OR Binary contains "6d0070007300730076006300" OR Binary contains "530065006e0073006500" OR Binary contains "450046005300" OR Binary contains "420044004500530056004300"))))
