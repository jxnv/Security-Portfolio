-- Title: Unix Shell Configuration Modification
-- ID: a94cdd87-6c54-4678-a6cc-2814ffe5a13d
-- Status: test
-- Level: medium
-- Author: Peter Matkovski, IAI
-- Date: 2023-03-06
-- Tags: attack.privilege-escalation, attack.persistence, attack.t1546.004
-- Description: Detect unix shell configuration modification. Adversaries may establish persistence through executing malicious commands triggered when a new shell is opened.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (type = 'PATH' AND (name = '/etc/shells' OR name = '/etc/profile' OR name = '/etc/profile.d/*' OR name = '/etc/bash.bashrc' OR name = '/etc/bashrc' OR name = '/etc/zsh/zprofile' OR name = '/etc/zsh/zshrc' OR name = '/etc/zsh/zlogin' OR name = '/etc/zsh/zlogout' OR name = '/etc/csh.cshrc' OR name = '/etc/csh.login' OR name = '/root/.bashrc' OR name = '/root/.bash_profile' OR name = '/root/.profile' OR name = '/root/.zshrc' OR name = '/root/.zprofile' OR name = '/home/*/.bashrc' OR name = '/home/*/.zshrc' OR name = '/home/*/.bash_profile' OR name = '/home/*/.zprofile' OR name = '/home/*/.profile' OR name = '/home/*/.bash_login' OR name = '/home/*/.bash_logout' OR name = '/home/*/.zlogin' OR name = '/home/*/.zlogout'))
