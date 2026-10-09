-- Title: Suspicious Processes Spawned by Java.EXE
-- ID: 0d34ed8b-1c12-4ff2-828c-16fc860b766d
-- Status: test
-- Level: high
-- Author: Andreas Hunkeler (@Karneades), Florian Roth
-- Date: 2021-12-17
-- Tags: attack.initial-access, attack.persistence, attack.privilege-escalation
-- Description: Detects suspicious processes spawned from a Java host process which could indicate a sign of exploitation (e.g. log4j)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (ParentImage ILIKE '%\\java.exe' AND (Image ILIKE '%\\AppVLP.exe' OR Image ILIKE '%\\bitsadmin.exe' OR Image ILIKE '%\\certutil.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\curl.exe' OR Image ILIKE '%\\forfiles.exe' OR Image ILIKE '%\\hh.exe' OR Image ILIKE '%\\mftrace.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\net.exe' OR Image ILIKE '%\\net1.exe' OR Image ILIKE '%\\query.exe' OR Image ILIKE '%\\reg.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\rundll32.exe' OR Image ILIKE '%\\schtasks.exe' OR Image ILIKE '%\\scrcons.exe' OR Image ILIKE '%\\scriptrunner.exe' OR Image ILIKE '%\\sh.exe' OR Image ILIKE '%\\systeminfo.exe' OR Image ILIKE '%\\whoami.exe' OR Image ILIKE '%\\wmic.exe' OR Image ILIKE '%\\wscript.exe'))
