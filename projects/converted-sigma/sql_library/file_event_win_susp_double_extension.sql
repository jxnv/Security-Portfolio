-- Title: Suspicious Double Extension Files
-- ID: b4926b47-a9d7-434c-b3a0-adc3fa0bd13e
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), frack113
-- Date: 2022-06-19
-- Tags: attack.stealth, attack.t1036.007
-- Description: Detects dropped files with double extensions, which is often used by malware as a method to abuse the fact that Windows hide default extensions by default.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((((TargetFilename ILIKE '%.rar.exe' OR TargetFilename ILIKE '%.zip.exe')) OR ((TargetFilename ILIKE '%.exe' OR TargetFilename ILIKE '%.iso' OR TargetFilename ILIKE '%.rar' OR TargetFilename ILIKE '%.svg' OR TargetFilename ILIKE '%.zip') AND (TargetFilename ILIKE '%.doc.%' OR TargetFilename ILIKE '%.docx.%' OR TargetFilename ILIKE '%.gif.%' OR TargetFilename ILIKE '%.jpeg.%' OR TargetFilename ILIKE '%.jpg.%' OR TargetFilename ILIKE '%.mp3.%' OR TargetFilename ILIKE '%.mp4.%' OR TargetFilename ILIKE '%.pdf.%' OR TargetFilename ILIKE '%.png.%' OR TargetFilename ILIKE '%.ppt.%' OR TargetFilename ILIKE '%.pptx.%' OR TargetFilename ILIKE '%.rtf.%' OR TargetFilename ILIKE '%.svg.%' OR TargetFilename ILIKE '%.txt.%' OR TargetFilename ILIKE '%.xls.%' OR TargetFilename ILIKE '%.xlsx.%'))) AND NOT ((TargetFilename ILIKE '/usr/share/icons/%')))
