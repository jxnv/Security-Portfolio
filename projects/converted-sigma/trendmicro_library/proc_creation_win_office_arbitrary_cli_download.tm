// Title: Potential Arbitrary File Download Using Office Application
// ID: 4ae3e30b-b03f-43aa-87e3-b622f4048eed
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems), Beyu Denis, oscd.community
// Date: 2022-05-17
// Tags: attack.stealth, attack.t1202
// Description: Detects potential arbitrary file download using a Microsoft Office application
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*http://*" OR CommandLine: "*https://*")) AND (((Image="*\\EXCEL.EXE" OR Image="*\\MSOXMLED.EXE" OR Image="*\\POWERPNT.EXE" OR Image="*\\WINWORD.exe")) OR ((OriginalFileName: "Excel.exe" OR OriginalFileName: "msoxmled.exe" OR OriginalFileName: "POWERPNT.EXE" OR OriginalFileName: "WinWord.exe"))))
