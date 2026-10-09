-- Title: Potential SAM Database Dump
-- ID: 4e87b8e2-2ee9-4b2a-a715-4727d297ece0
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-11
-- Tags: attack.credential-access, attack.t1003.002
-- Description: Detects the creation of files that look like exports of the local SAM (Security Account Manager)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetFilename="*\\Temp\\sam" OR TargetFilename="*\\sam.sav" OR TargetFilename="*\\Intel\\sam" OR TargetFilename="*\\sam.hive" OR TargetFilename="*\\Perflogs\\sam" OR TargetFilename="*\\ProgramData\\sam" OR TargetFilename="*\\Users\\Public\\sam" OR TargetFilename="*\\AppData\\Local\\sam" OR TargetFilename="*\\AppData\\Roaming\\sam" OR TargetFilename="*_ShadowSteal.zip" OR TargetFilename="*\\Documents\\SAM.export" OR TargetFilename="*:\\sam")) OR ((TargetFilename LIKE '%\\hive_sam_%' OR TargetFilename LIKE '%\\sam.save%' OR TargetFilename LIKE '%\\sam.export%' OR TargetFilename LIKE '%\\~reg_sam.save%' OR TargetFilename LIKE '%\\sam_backup%' OR TargetFilename LIKE '%\\sam.bck%' OR TargetFilename LIKE '%\\sam.backup%')))
