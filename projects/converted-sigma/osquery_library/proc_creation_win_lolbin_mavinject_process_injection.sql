-- Title: Mavinject Inject DLL Into Running Process
-- ID: 4f73421b-5a0b-4bbf-a892-5a7fb99bea66
-- Status: test
-- Level: high
-- Author: frack113, Florian Roth
-- Date: 2021-07-12
-- Tags: attack.privilege-escalation, attack.stealth, attack.t1055.001, attack.t1218.013
-- Description: Detects process injection using the signed Windows tool "Mavinject" via the "INJECTRUNNING" flag
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((CommandLine LIKE '% /INJECTRUNNING %') AND NOT ((ParentImage = 'C:\\Windows\\System32\\AppVClient.exe')))
