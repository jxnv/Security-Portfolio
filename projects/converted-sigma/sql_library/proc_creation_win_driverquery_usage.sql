-- Title: DriverQuery.EXE Execution
-- ID: a20def93-0709-4eae-9bd2-31206e21e6b2
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-19
-- Tags: attack.discovery
-- Description: Detect usage of the "driverquery" utility. Which can be used to perform reconnaissance on installed drivers
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%driverquery.exe') OR (OriginalFileName = 'drvqry.exe')) AND NOT ((((ParentImage ILIKE '%\\cscript.exe' OR ParentImage ILIKE '%\\mshta.exe' OR ParentImage ILIKE '%\\regsvr32.exe' OR ParentImage ILIKE '%\\rundll32.exe' OR ParentImage ILIKE '%\\wscript.exe')) OR ((ParentImage ILIKE '%\\AppData\\Local\\%' OR ParentImage ILIKE '%\\Users\\Public\\%' OR ParentImage ILIKE '%\\Windows\\Temp\\%')))))
