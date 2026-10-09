-- Title: Potential Homoglyph Attack Using Lookalike Characters in Filename
-- ID: 4f1707b1-b50b-45b4-b5a2-3978b5a5d0d6
-- Status: test
-- Level: medium
-- Author: Micah Babinski, @micahbabinski
-- Date: 2023-05-08
-- Tags: attack.stealth, attack.t1036, attack.t1036.003
-- Description: Detects the presence of unicode characters which are homoglyphs, or identical in appearance, to ASCII letter characters.
-- This is used as an obfuscation and masquerading techniques. Only "perfect" homoglyphs are included; these are characters that
-- are indistinguishable from ASCII characters and thus may make excellent candidates for homoglyph attack characters.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE (((TargetFilename LIKE '%а%' OR TargetFilename LIKE '%е%' OR TargetFilename LIKE '%о%' OR TargetFilename LIKE '%р%' OR TargetFilename LIKE '%с%' OR TargetFilename LIKE '%х%' OR TargetFilename LIKE '%ѕ%' OR TargetFilename LIKE '%і%' OR TargetFilename LIKE '%ӏ%' OR TargetFilename LIKE '%ј%' OR TargetFilename LIKE '%һ%' OR TargetFilename LIKE '%ԁ%' OR TargetFilename LIKE '%ԛ%' OR TargetFilename LIKE '%ԝ%' OR TargetFilename LIKE '%ο%')) OR ((TargetFilename LIKE '%А%' OR TargetFilename LIKE '%В%' OR TargetFilename LIKE '%Е%' OR TargetFilename LIKE '%К%' OR TargetFilename LIKE '%М%' OR TargetFilename LIKE '%Н%' OR TargetFilename LIKE '%О%' OR TargetFilename LIKE '%Р%' OR TargetFilename LIKE '%С%' OR TargetFilename LIKE '%Т%' OR TargetFilename LIKE '%Х%' OR TargetFilename LIKE '%Ѕ%' OR TargetFilename LIKE '%І%' OR TargetFilename LIKE '%Ј%' OR TargetFilename LIKE '%Ү%' OR TargetFilename LIKE '%Ӏ%' OR TargetFilename LIKE '%Ԍ%' OR TargetFilename LIKE '%Ԛ%' OR TargetFilename LIKE '%Ԝ%' OR TargetFilename LIKE '%Α%' OR TargetFilename LIKE '%Β%' OR TargetFilename LIKE '%Ε%' OR TargetFilename LIKE '%Ζ%' OR TargetFilename LIKE '%Η%' OR TargetFilename LIKE '%Ι%' OR TargetFilename LIKE '%Κ%' OR TargetFilename LIKE '%Μ%' OR TargetFilename LIKE '%Ν%' OR TargetFilename LIKE '%Ο%' OR TargetFilename LIKE '%Ρ%' OR TargetFilename LIKE '%Τ%' OR TargetFilename LIKE '%Υ%' OR TargetFilename LIKE '%Χ%')))
