-- Title: Use NTFS Short Name in Image
-- ID: 3ef5605c-9eb9-47b0-9a71-b727e6aa5c3b
-- Status: test
-- Level: medium
-- Author: frack113, Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-08-06
-- Tags: attack.stealth, attack.t1564.004
-- Description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image based detection
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image LIKE '%~1.bat%' OR Image LIKE '%~1.dll%' OR Image LIKE '%~1.exe%' OR Image LIKE '%~1.hta%' OR Image LIKE '%~1.js%' OR Image LIKE '%~1.msi%' OR Image LIKE '%~1.ps1%' OR Image LIKE '%~1.tmp%' OR Image LIKE '%~1.vbe%' OR Image LIKE '%~1.vbs%' OR Image LIKE '%~2.bat%' OR Image LIKE '%~2.dll%' OR Image LIKE '%~2.exe%' OR Image LIKE '%~2.hta%' OR Image LIKE '%~2.js%' OR Image LIKE '%~2.msi%' OR Image LIKE '%~2.ps1%' OR Image LIKE '%~2.tmp%' OR Image LIKE '%~2.vbe%' OR Image LIKE '%~2.vbs%')) AND NOT ((ParentImage = 'C:\\Windows\\explorer.exe')) AND NOT (((ParentImage="*\\thor\\thor64.exe") OR (Image="*\\VCREDI~1.EXE") OR (ParentImage="*\\WebEx\\WebexHost.exe") OR (Image = 'C:\\PROGRA~1\\WinZip\\WZPREL~1.EXE'))))
