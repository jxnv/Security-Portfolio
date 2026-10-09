-- Title: Potential Python DLL SideLoading
-- ID: d36f7c12-14a3-4d48-b6b8-774b9c66f44d
-- Status: test
-- Level: medium
-- Author: Swachchhanda Shrawan Poudel
-- Date: 2024-10-06
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574.001
-- Description: Detects potential DLL sideloading of Python DLL files.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((ImageLoaded ILIKE '%\\python39.dll' OR ImageLoaded ILIKE '%\\python310.dll' OR ImageLoaded ILIKE '%\\python311.dll' OR ImageLoaded ILIKE '%\\python312.dll')) AND NOT (((((ImageLoaded ILIKE 'C:\\Program Files\\Python3%' OR ImageLoaded ILIKE 'C:\\Program Files (x86)\\Python3%')) OR (ImageLoaded ILIKE '%\\AppData\\Local\\Programs\\Python\\Python3%')) OR (Product = 'Python' AND Signed = 'true' AND Description = 'Python' AND Company = 'Python Software Foundation'))) AND NOT (((ImageLoaded ILIKE 'C:\\ProgramData\\Anaconda3\\%') OR ((ImageLoaded ILIKE '%\\cpython\\externals\\%' OR ImageLoaded ILIKE '%\\cpython\\PCbuild\\%')) OR (ImageLoaded ILIKE 'C:\\Users%' AND ImageLoaded ILIKE '%\\AppData\\Local\\Temp\\_MEI%') OR (ImageLoaded ILIKE 'C:\\Program Files\\Microsoft Visual Studio\\%'))))
