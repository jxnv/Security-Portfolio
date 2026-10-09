-- Title: Potential Homoglyph Attack Using Lookalike Characters
-- ID: 32e280f1-8ad4-46ef-9e80-910657611fbc
-- Status: test
-- Level: medium
-- Author: Micah Babinski, @micahbabinski
-- Date: 2023-05-07
-- Tags: attack.stealth, attack.t1036, attack.t1036.003
-- Description: Detects the presence of unicode characters which are homoglyphs, or identical in appearance, to ASCII letter characters.
-- This is used as an obfuscation and masquerading techniques. Only "perfect" homoglyphs are included; these are characters that
-- are indistinguishable from ASCII characters and thus may make excellent candidates for homoglyph attack characters.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%а%' OR CommandLine ILIKE '%е%' OR CommandLine ILIKE '%о%' OR CommandLine ILIKE '%р%' OR CommandLine ILIKE '%с%' OR CommandLine ILIKE '%х%' OR CommandLine ILIKE '%ѕ%' OR CommandLine ILIKE '%і%' OR CommandLine ILIKE '%ӏ%' OR CommandLine ILIKE '%ј%' OR CommandLine ILIKE '%һ%' OR CommandLine ILIKE '%ԁ%' OR CommandLine ILIKE '%ԛ%' OR CommandLine ILIKE '%ԝ%' OR CommandLine ILIKE '%ο%')) OR ((CommandLine ILIKE '%А%' OR CommandLine ILIKE '%В%' OR CommandLine ILIKE '%Е%' OR CommandLine ILIKE '%К%' OR CommandLine ILIKE '%М%' OR CommandLine ILIKE '%Н%' OR CommandLine ILIKE '%О%' OR CommandLine ILIKE '%Р%' OR CommandLine ILIKE '%С%' OR CommandLine ILIKE '%Т%' OR CommandLine ILIKE '%Х%' OR CommandLine ILIKE '%Ѕ%' OR CommandLine ILIKE '%І%' OR CommandLine ILIKE '%Ј%' OR CommandLine ILIKE '%Ү%' OR CommandLine ILIKE '%Ӏ%' OR CommandLine ILIKE '%Ԍ%' OR CommandLine ILIKE '%Ԛ%' OR CommandLine ILIKE '%Ԝ%' OR CommandLine ILIKE '%Α%' OR CommandLine ILIKE '%Β%' OR CommandLine ILIKE '%Ε%' OR CommandLine ILIKE '%Ζ%' OR CommandLine ILIKE '%Η%' OR CommandLine ILIKE '%Ι%' OR CommandLine ILIKE '%Κ%' OR CommandLine ILIKE '%Μ%' OR CommandLine ILIKE '%Ν%' OR CommandLine ILIKE '%Ο%' OR CommandLine ILIKE '%Ρ%' OR CommandLine ILIKE '%Τ%' OR CommandLine ILIKE '%Υ%' OR CommandLine ILIKE '%Χ%')))
