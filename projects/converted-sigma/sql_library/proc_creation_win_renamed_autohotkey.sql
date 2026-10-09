-- Title: Renamed AutoHotkey.EXE Execution
-- ID: 0f16d9cf-0616-45c8-8fad-becc11b5a41c
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali
-- Date: 2023-02-07
-- Tags: attack.stealth
-- Description: Detects execution of a renamed autohotkey.exe binary based on PE metadata fields
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Product ILIKE '%AutoHotkey%') OR (Description ILIKE '%AutoHotkey%') OR ((OriginalFileName = 'AutoHotkey.exe' OR OriginalFileName = 'AutoHotkey.rc'))) AND NOT ((((Image ILIKE '%\\AutoHotkey.exe' OR Image ILIKE '%\\AutoHotkey32.exe' OR Image ILIKE '%\\AutoHotkey32_UIA.exe' OR Image ILIKE '%\\AutoHotkey64.exe' OR Image ILIKE '%\\AutoHotkey64_UIA.exe' OR Image ILIKE '%\\AutoHotkeyA32.exe' OR Image ILIKE '%\\AutoHotkeyA32_UIA.exe' OR Image ILIKE '%\\AutoHotkeyU32.exe' OR Image ILIKE '%\\AutoHotkeyU32_UIA.exe' OR Image ILIKE '%\\AutoHotkeyU64.exe' OR Image ILIKE '%\\AutoHotkeyU64_UIA.exe')) OR (Image ILIKE '%\\AutoHotkey%'))))
