-- Title: Legitimate Application Dropped Script
-- ID: 7d604714-e071-49ff-8726-edeb95a70679
-- Status: test
-- Level: high
-- Author: frack113, Florian Roth (Nextron Systems)
-- Date: 2022-08-21
-- Tags: attack.stealth, attack.t1218
-- Description: Detects LOLBINs and applications that should not legitimately drop script files to disk.
-- This may indicate malware staging or abuse of a trusted binary for script-based code execution.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((Image ILIKE '%\\eqnedt32.exe' OR Image ILIKE '%\\wordpad.exe' OR Image ILIKE '%\\wordview.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\certoc.exe' OR Image ILIKE '%\\CertReq.exe' OR Image ILIKE '%\\Desktopimgdownldr.exe' OR Image ILIKE '%\\esentutl.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\AcroRd32.exe' OR Image ILIKE '%\\RdrCEF.exe' OR Image ILIKE '%\\hh.exe' OR Image ILIKE '%\\finger.exe') AND (TargetFilename ILIKE '%.bat' OR TargetFilename ILIKE '%.chm' OR TargetFilename ILIKE '%.csproj' OR TargetFilename ILIKE '%.hta' OR TargetFilename ILIKE '%.js' OR TargetFilename ILIKE '%.jse' OR TargetFilename ILIKE '%.proj' OR TargetFilename ILIKE '%.ps1' OR TargetFilename ILIKE '%.py' OR TargetFilename ILIKE '%.scf' OR TargetFilename ILIKE '%.vbe' OR TargetFilename ILIKE '%.vbs' OR TargetFilename ILIKE '%.wsf' OR TargetFilename ILIKE '%.wsh')) AND NOT ((Image ILIKE '%\\mshta.exe' AND TargetFilename ILIKE '%.hta')))
