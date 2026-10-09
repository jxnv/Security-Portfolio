-- Title: Potential Persistence Via Excel Add-in - Registry
-- ID: 961e33d1-4f86-4fcf-80ab-930a708b2f82
-- Status: test
-- Level: high
-- Author: frack113
-- Date: 2023-01-15
-- Tags: attack.persistence, attack.t1137.006
-- Description: Detect potential persistence via the creation of an excel add-in (XLL) file to make it run automatically when Excel is started.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (TargetObject ILIKE '%Software\\Microsoft\\Office\\%' AND TargetObject ILIKE '%\\Excel\\Options' AND Details ILIKE '/R %' AND Details ILIKE '%.xll')
