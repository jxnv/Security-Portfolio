-- Title: Potential Persistence Via Microsoft Office Add-In
-- ID: 8e1cb247-6cf6-42fa-b440-3f27d57e9936
-- Status: test
-- Level: high
-- Author: NVISO
-- Date: 2020-05-11
-- Tags: attack.persistence, attack.t1137.006
-- Description: Detects potential persistence activity via startup add-ins that load when Microsoft Office starts (.wll/.xll are simply .dll fit for Word or Excel).
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((TargetFilename ILIKE '%\\Microsoft\\Addins\\%' AND (TargetFilename ILIKE '%.xlam' OR TargetFilename ILIKE '%.xla' OR TargetFilename ILIKE '%.ppam')) OR (TargetFilename ILIKE '%\\Microsoft\\Word\\Startup\\%' AND TargetFilename ILIKE '%.wll') OR (TargetFilename ILIKE '%Microsoft\\Excel\\XLSTART\\%' AND TargetFilename ILIKE '%.xlam') OR (TargetFilename ILIKE '%\\Microsoft\\Excel\\Startup\\%' AND TargetFilename ILIKE '%.xll'))
