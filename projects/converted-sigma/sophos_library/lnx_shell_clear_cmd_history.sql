-- Title: Linux Command History Tampering
-- ID: fdc88d25-96fb-4b7c-9633-c0e417fdbd4e
-- Status: test
-- Level: high
-- Author: Patrick Bareiss
-- Date: 2019-03-24
-- Tags: attack.stealth, attack.t1070.003
-- Description: Detects commands that try to clear or tamper with the Linux command history.
-- This technique is used by threat actors in order to evade defenses and execute commands without them being recorded in files such as "bash_history" or "zsh_history".
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ("cat /dev/null >*sh_history" OR "cat /dev/zero >*sh_history" OR "chattr +i*sh_history" OR "echo \"\" >*sh_history" OR "empty_bash_history" OR "export HISTFILESIZE=0" OR "history -c" OR "history -w" OR "ln -sf /dev/null *sh_history" OR "ln -sf /dev/zero *sh_history" OR "rm *sh_history" OR "shopt -ou history" OR "shopt -uo history" OR "shred *sh_history" OR "truncate -s0 *sh_history")
