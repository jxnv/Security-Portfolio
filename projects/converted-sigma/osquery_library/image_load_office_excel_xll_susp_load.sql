-- Title: Microsoft Excel Add-In Loaded From Uncommon Location
-- ID: af4c4609-5755-42fe-8075-4effb49f5d44
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-05-12
-- Tags: attack.execution, attack.t1204.002
-- Description: Detects Microsoft Excel loading an Add-In (.xll) file from an uncommon location
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (Image="*\\excel.exe" AND (ImageLoaded LIKE '%\\Desktop\\%' OR ImageLoaded LIKE '%\\Downloads\\%' OR ImageLoaded LIKE '%\\Perflogs\\%' OR ImageLoaded LIKE '%\\Temp\\%' OR ImageLoaded LIKE '%\\Users\\Public\\%' OR ImageLoaded LIKE '%\\Windows\\Tasks\\%') AND ImageLoaded="*.xll")
