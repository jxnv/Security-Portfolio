-- Title: Suspicious Shells Spawn by Java Utility Keytool
-- ID: 90fb5e62-ca1f-4e22-b42e-cc521874c938
-- Status: test
-- Level: high
-- Author: Andreas Hunkeler (@Karneades)
-- Date: 2021-12-22
-- Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
-- Description: Detects suspicious shell spawn from Java utility keytool process (e.g. adselfservice plus exploitation)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (ParentImage ILIKE '%\\keytool.exe' AND (Image ILIKE '%\\cmd.exe' OR Image ILIKE '%\\sh.exe' OR Image ILIKE '%\\bash.exe' OR Image ILIKE '%\\powershell.exe' OR Image ILIKE '%\\pwsh.exe' OR Image ILIKE '%\\schtasks.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\whoami.exe' OR Image ILIKE '%\\bitsadmin.exe' OR Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\scrcons.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\hh.exe' OR Image ILIKE '%\\wmic.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\forfiles.exe' OR Image ILIKE '%\\scriptrunner.exe' OR Image ILIKE '%\\mftrace.exe' OR Image ILIKE '%\\AppVLP.exe' OR Image ILIKE '%\\systeminfo.exe' OR Image ILIKE '%\\reg.exe' OR Image ILIKE '%\\query.exe'))
