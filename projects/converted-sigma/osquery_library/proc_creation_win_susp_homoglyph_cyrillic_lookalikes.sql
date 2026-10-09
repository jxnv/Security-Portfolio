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

SELECT * FROM processes WHERE (((CommandLine LIKE '%а%' OR CommandLine LIKE '%е%' OR CommandLine LIKE '%о%' OR CommandLine LIKE '%р%' OR CommandLine LIKE '%с%' OR CommandLine LIKE '%х%' OR CommandLine LIKE '%ѕ%' OR CommandLine LIKE '%і%' OR CommandLine LIKE '%ӏ%' OR CommandLine LIKE '%ј%' OR CommandLine LIKE '%һ%' OR CommandLine LIKE '%ԁ%' OR CommandLine LIKE '%ԛ%' OR CommandLine LIKE '%ԝ%' OR CommandLine LIKE '%ο%')) OR ((CommandLine LIKE '%А%' OR CommandLine LIKE '%В%' OR CommandLine LIKE '%Е%' OR CommandLine LIKE '%К%' OR CommandLine LIKE '%М%' OR CommandLine LIKE '%Н%' OR CommandLine LIKE '%О%' OR CommandLine LIKE '%Р%' OR CommandLine LIKE '%С%' OR CommandLine LIKE '%Т%' OR CommandLine LIKE '%Х%' OR CommandLine LIKE '%Ѕ%' OR CommandLine LIKE '%І%' OR CommandLine LIKE '%Ј%' OR CommandLine LIKE '%Ү%' OR CommandLine LIKE '%Ӏ%' OR CommandLine LIKE '%Ԍ%' OR CommandLine LIKE '%Ԛ%' OR CommandLine LIKE '%Ԝ%' OR CommandLine LIKE '%Α%' OR CommandLine LIKE '%Β%' OR CommandLine LIKE '%Ε%' OR CommandLine LIKE '%Ζ%' OR CommandLine LIKE '%Η%' OR CommandLine LIKE '%Ι%' OR CommandLine LIKE '%Κ%' OR CommandLine LIKE '%Μ%' OR CommandLine LIKE '%Ν%' OR CommandLine LIKE '%Ο%' OR CommandLine LIKE '%Ρ%' OR CommandLine LIKE '%Τ%' OR CommandLine LIKE '%Υ%' OR CommandLine LIKE '%Χ%')))
