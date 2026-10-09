// Title: Remote Access Tool - NetSupport Execution From Unusual Location
// ID: 37e8d358-6408-4853-82f4-98333fca7014
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-19
// Tags: attack.stealth
// Description: Detects execution of client32.exe (NetSupport RAT) from an unusual location (outside of 'C:\Program Files')
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\client32.exe") OR (Product contains "NetSupport Remote Control") OR (OriginalFileName contains "client32.exe") OR (Hashes contains "IMPHASH=a9d50692e95b79723f3e76fcf70d023e")) AND NOT (((Image="C:\\Program Files\\*" OR Image="C:\\Program Files (x86)\\*"))))
