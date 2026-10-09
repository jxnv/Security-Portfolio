// Title: Potential Rundll32 Execution With DLL Stored In ADS
// ID: 9248c7e1-2bf3-4661-a22c-600a8040b446
// Status: test
// Level: high
// Author: Harjot Singh, '@cyb3rjy0t'
// Date: 2023-01-21
// Tags: attack.stealth, attack.t1564.004
// Description: Detects execution of rundll32 where the DLL being called is stored in an Alternate Data Stream (ADS).
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine=regex("[Rr][Uu][Nn][Dd][Ll][Ll]32(?:\\.[Ee][Xx][Ee])? \\S+?\\w:\\S+?:")) AND ((Image="*\\rundll32.exe") OR (OriginalFileName == "RUNDLL32.EXE")))
