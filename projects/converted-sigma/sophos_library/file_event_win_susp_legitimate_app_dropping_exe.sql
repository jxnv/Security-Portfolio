-- Title: Legitimate Application Dropped Executable
-- ID: f0540f7e-2db3-4432-b9e0-3965486744bc
-- Status: test
-- Level: high
-- Author: frack113, Florian Roth (Nextron Systems)
-- Date: 2022-08-21
-- Tags: attack.stealth, attack.t1218
-- Description: Detects LOLBINs and applications that should not legitimately drop executable or executable-equivalent files to disk.
-- This may indicate malware staging, process injection, or abuse of a trusted binary for payload delivery.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\eqnedt32.exe' OR Image ILIKE '%\\wordpad.exe' OR Image ILIKE '%\\wordview.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\certoc.exe' OR Image ILIKE '%\\CertReq.exe' OR Image ILIKE '%\\Desktopimgdownldr.exe' OR Image ILIKE '%\\esentutl.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\AcroRd32.exe' OR Image ILIKE '%\\RdrCEF.exe' OR Image ILIKE '%\\hh.exe' OR Image ILIKE '%\\finger.exe') AND (TargetFilename ILIKE '%.com' OR TargetFilename ILIKE '%.dll' OR TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.jar' OR TargetFilename ILIKE '%.ocx' OR TargetFilename ILIKE '%.pyc'))
