-- Title: Potential SAM Database Dump
-- ID: 4e87b8e2-2ee9-4b2a-a715-4727d297ece0
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-02-11
-- Tags: attack.credential-access, attack.t1003.002
-- Description: Detects the creation of files that look like exports of the local SAM (Security Account Manager)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetFilename ILIKE '%\\Temp\\sam' OR TargetFilename ILIKE '%\\sam.sav' OR TargetFilename ILIKE '%\\Intel\\sam' OR TargetFilename ILIKE '%\\sam.hive' OR TargetFilename ILIKE '%\\Perflogs\\sam' OR TargetFilename ILIKE '%\\ProgramData\\sam' OR TargetFilename ILIKE '%\\Users\\Public\\sam' OR TargetFilename ILIKE '%\\AppData\\Local\\sam' OR TargetFilename ILIKE '%\\AppData\\Roaming\\sam' OR TargetFilename ILIKE '%_ShadowSteal.zip' OR TargetFilename ILIKE '%\\Documents\\SAM.export' OR TargetFilename ILIKE '%:\\sam')) OR ((TargetFilename ILIKE '%\\hive_sam_%' OR TargetFilename ILIKE '%\\sam.save%' OR TargetFilename ILIKE '%\\sam.export%' OR TargetFilename ILIKE '%\\~reg_sam.save%' OR TargetFilename ILIKE '%\\sam_backup%' OR TargetFilename ILIKE '%\\sam.bck%' OR TargetFilename ILIKE '%\\sam.backup%')))
