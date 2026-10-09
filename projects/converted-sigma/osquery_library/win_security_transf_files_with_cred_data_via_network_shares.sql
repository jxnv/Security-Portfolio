-- Title: Transferring Files with Credential Data via Network Shares
-- ID: 910ab938-668b-401b-b08c-b596e80fdca5
-- Status: test
-- Level: medium
-- Author: Teymur Kheirkhabarov, oscd.community
-- Date: 2019-10-22
-- Tags: attack.credential-access, attack.t1003.002, attack.t1003.001, attack.t1003.003
-- Description: Transferring files with well-known filenames (sensitive files with credential data) using network shares
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((EventID = '5145') AND (((RelativeTargetName LIKE '%\\mimidrv%' OR RelativeTargetName LIKE '%\\lsass%' OR RelativeTargetName LIKE '%\\windows\\minidump\\%' OR RelativeTargetName LIKE '%\\hiberfil%' OR RelativeTargetName LIKE '%\\sqldmpr%')) OR ((RelativeTargetName = 'Windows\\NTDS\\ntds.dit' OR RelativeTargetName = 'Windows\\System32\\config\\SAM' OR RelativeTargetName = 'Windows\\System32\\config\\SECURITY' OR RelativeTargetName = 'Windows\\System32\\config\\SYSTEM'))))
