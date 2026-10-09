-- Title: Startup Folder File Write
-- ID: 2aa0a6b4-a865-495b-ab51-c28249537b75
-- Status: test
-- Level: medium
-- Author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
-- Date: 2020-05-02
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
-- Description: A General detection for files being created in the Windows startup directory. This could be an indicator of persistence.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetFilename LIKE '%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp%') AND NOT ((((Image = 'C:\\Windows\\System32\\wuauclt.exe' OR Image = 'C:\\Windows\\uus\\ARM64\\wuaucltcore.exe')) OR ((TargetFilename="C:\\$WINDOWS.~BT\\NewOS\\*" OR TargetFilename="C:\\$WinREAgent\\Scratch\\Mount\\*")))) AND NOT ((Image="*\\ONENOTE.EXE" AND TargetFilename="*\\Send to OneNote.lnk")))
