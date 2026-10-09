-- Title: Weak Encryption Enabled and Kerberoast
-- ID: f6de9536-0441-4b3f-a646-f4e00f300ffd
-- Status: test
-- Level: high
-- Author: @neu5ron
-- Date: 2017-07-30
-- Tags: attack.defense-impairment, attack.t1685
-- Description: Detects scenario where weak encryption is enabled for a user profile which could be used for hash/password cracking.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((EventID = 4738) AND ((((NewUacValue ILIKE '%8???' OR NewUacValue ILIKE '%9???' OR NewUacValue ILIKE '%A???' OR NewUacValue ILIKE '%B???' OR NewUacValue ILIKE '%C???' OR NewUacValue ILIKE '%D???' OR NewUacValue ILIKE '%E???' OR NewUacValue ILIKE '%F???')) AND NOT (((OldUacValue ILIKE '%8???' OR OldUacValue ILIKE '%9???' OR OldUacValue ILIKE '%A???' OR OldUacValue ILIKE '%B???' OR OldUacValue ILIKE '%C???' OR OldUacValue ILIKE '%D???' OR OldUacValue ILIKE '%E???' OR OldUacValue ILIKE '%F???')))) OR (((NewUacValue ILIKE '%1????' OR NewUacValue ILIKE '%3????' OR NewUacValue ILIKE '%5????' OR NewUacValue ILIKE '%7????' OR NewUacValue ILIKE '%9????' OR NewUacValue ILIKE '%B????' OR NewUacValue ILIKE '%D????' OR NewUacValue ILIKE '%F????')) AND NOT (((OldUacValue ILIKE '%1????' OR OldUacValue ILIKE '%3????' OR OldUacValue ILIKE '%5????' OR OldUacValue ILIKE '%7????' OR OldUacValue ILIKE '%9????' OR OldUacValue ILIKE '%B????' OR OldUacValue ILIKE '%D????' OR OldUacValue ILIKE '%F????')))) OR (((NewUacValue ILIKE '%8??' OR NewUacValue ILIKE '%9??' OR NewUacValue ILIKE '%A??' OR NewUacValue ILIKE '%B??' OR NewUacValue ILIKE '%C??' OR NewUacValue ILIKE '%D??' OR NewUacValue ILIKE '%E??' OR NewUacValue ILIKE '%F??')) AND NOT (((OldUacValue ILIKE '%8??' OR OldUacValue ILIKE '%9??' OR OldUacValue ILIKE '%A??' OR OldUacValue ILIKE '%B??' OR OldUacValue ILIKE '%C??' OR OldUacValue ILIKE '%D??' OR OldUacValue ILIKE '%E??' OR OldUacValue ILIKE '%F??'))))))
