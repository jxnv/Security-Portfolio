-- Title: DotNet CLR DLL Loaded By Scripting Applications
-- ID: 4508a70e-97ef-4300-b62b-ff27992990ea
-- Status: test
-- Level: high
-- Author: omkar72, oscd.community
-- Date: 2020-10-14
-- Tags: attack.execution, attack.privilege-escalation, attack.stealth, attack.t1055
-- Description: Detects .NET CLR DLLs being loaded by scripting applications such as wscript or cscript. This could be an indication of potential suspicious execution.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%\\cmstp.exe' OR Image ILIKE '%\\cscript.exe' OR Image ILIKE '%\\mshta.exe' OR Image ILIKE '%\\msxsl.exe' OR Image ILIKE '%\\regsvr32.exe' OR Image ILIKE '%\\wmic.exe' OR Image ILIKE '%\\wscript.exe') AND (ImageLoaded ILIKE '%\\clr.dll' OR ImageLoaded ILIKE '%\\mscoree.dll' OR ImageLoaded ILIKE '%\\mscorlib.dll'))
