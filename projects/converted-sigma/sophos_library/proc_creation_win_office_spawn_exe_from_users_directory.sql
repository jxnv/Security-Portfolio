-- Title: Suspicious Binary In User Directory Spawned From Office Application
-- ID: aa3a6f94-890e-4e22-b634-ffdfd54792cc
-- Status: test
-- Level: high
-- Author: Jason Lynch
-- Date: 2019-04-02
-- Tags: attack.execution, attack.t1204.002, attack.g0046, car.2013-05-002
-- Description: Detects an executable in the users directory started from one of the Microsoft Office suite applications (Word, Excel, PowerPoint, Publisher, Visio)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((ParentImage ILIKE '%\\WINWORD.EXE' OR ParentImage ILIKE '%\\EXCEL.EXE' OR ParentImage ILIKE '%\\POWERPNT.exe' OR ParentImage ILIKE '%\\MSPUB.exe' OR ParentImage ILIKE '%\\VISIO.exe' OR ParentImage ILIKE '%\\MSACCESS.exe' OR ParentImage ILIKE '%\\EQNEDT32.exe') AND Image ILIKE 'C:\\users\\%' AND Image ILIKE '%.exe') AND NOT ((Image ILIKE '%\\Teams.exe')))
