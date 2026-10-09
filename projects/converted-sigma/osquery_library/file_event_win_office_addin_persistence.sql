-- Title: Potential Persistence Via Microsoft Office Add-In
-- ID: 8e1cb247-6cf6-42fa-b440-3f27d57e9936
-- Status: test
-- Level: high
-- Author: NVISO
-- Date: 2020-05-11
-- Tags: attack.persistence, attack.t1137.006
-- Description: Detects potential persistence activity via startup add-ins that load when Microsoft Office starts (.wll/.xll are simply .dll fit for Word or Excel).
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((TargetFilename LIKE '%\\Microsoft\\Addins\\%' AND (TargetFilename="*.xlam" OR TargetFilename="*.xla" OR TargetFilename="*.ppam")) OR (TargetFilename LIKE '%\\Microsoft\\Word\\Startup\\%' AND TargetFilename="*.wll") OR (TargetFilename LIKE '%Microsoft\\Excel\\XLSTART\\%' AND TargetFilename="*.xlam") OR (TargetFilename LIKE '%\\Microsoft\\Excel\\Startup\\%' AND TargetFilename="*.xll"))
