-- Title: Suspicious Path In Keyboard Layout IME File Registry Value
-- ID: 9d8f9bb8-01af-4e15-a3a2-349071530530
-- Status: test
-- Level: high
-- Author: X__Junior (Nextron Systems)
-- Date: 2023-11-21
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects usage of Windows Input Method Editor (IME) keyboard layout feature, which allows an attacker to load a DLL into the process after sending the WM_INPUTLANGCHANGEREQUEST message.
-- Before doing this, the client needs to register the DLL in a special registry key that is assumed to implement this keyboard layout. This registry key should store a value named "Ime File" with a DLL path.
-- IMEs are essential for languages that have more characters than can be represented on a standard keyboard, such as Chinese, Japanese, and Korean.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((TargetObject ILIKE '%\\Control\\Keyboard Layouts\\%' AND TargetObject ILIKE '%Ime File%')) AND (((Details ILIKE '%:\\Perflogs\\%' OR Details ILIKE '%:\\Users\\Public\\%' OR Details ILIKE '%:\\Windows\\Temp\\%' OR Details ILIKE '%\\AppData\\Local\\Temp\\%' OR Details ILIKE '%\\AppData\\Roaming\\%' OR Details ILIKE '%\\Temporary Internet%')) OR (((Details ILIKE '%:\\Users\\%' AND Details ILIKE '%\\Favorites\\%')) OR ((Details ILIKE '%:\\Users\\%' AND Details ILIKE '%\\Favourites\\%')) OR ((Details ILIKE '%:\\Users\\%' AND Details ILIKE '%\\Contacts\\%')))))
