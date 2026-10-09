-- Title: ISO or Image Mount Indicator in Recent Files
-- ID: 4358e5a5-7542-4dcb-b9f3-87667371839b
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-11
-- Tags: attack.initial-access, attack.t1566.001
-- Description: Detects the creation of recent element file that points to an .ISO, .IMG, .VHD or .VHDX file as often used in phishing attacks.
-- This can be a false positive on server systems but on workstations users should rarely mount .iso or .img files.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetFilename="*.iso.lnk" OR TargetFilename="*.img.lnk" OR TargetFilename="*.vhd.lnk" OR TargetFilename="*.vhdx.lnk") AND TargetFilename LIKE '%\\Microsoft\\Windows\\Recent\\%')
