-- Title: ImagingDevices Unusual Parent/Child Processes
-- ID: f11f2808-adb4-46c0-802a-8660db50fa99
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-09-27
-- Tags: attack.execution, attack.stealth
-- Description: Detects unusual parent or children of the ImagingDevices.exe (Windows Contacts) process as seen being used with Bumblebee activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\ImagingDevices.exe') OR ((ParentImage ILIKE '%\\WmiPrvSE.exe' OR ParentImage ILIKE '%\\svchost.exe' OR ParentImage ILIKE '%\\dllhost.exe') AND Image ILIKE '%\\ImagingDevices.exe'))
