-- ============================================================================
--  MIRAGE — ATT&CK Technique Signature Seeds (30 patterns)
-- ============================================================================
--  Each row maps a regex pattern to a MITRE ATT&CK technique ID and name.
--  The ingestion pipeline matches every command against these patterns to
--  populate the session_techniques junction table.
--
--  Reference: https://attack.mitre.org/techniques/enterprise/
-- ============================================================================

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:cat|head|tail|less|more|strings|grep).*\/etc\/(?:passwd|shadow)', 'T1003.008', 'OS Credential Dumping: /etc/passwd & /etc/shadow');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:uname|hostnamectl|lsb_release|cat\s+\/etc\/(?:issue|os-release|redhat-release)|arch|lscpu|dmidecode)', 'T1082', 'System Information Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:whoami|\bwho\b|\bw\b|\bid\b|\busers\b|\blast\b|\bfinger\b)', 'T1033', 'System Owner/User Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:ifconfig|ip\s+(?:addr|route|link)|route\b|arp\b|cat\s+\/etc\/resolv\.conf|nmcli)', 'T1016', 'System Network Configuration Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:netstat\s+-[antup]+|ss\s+-[tulnap]+|lsof\s+-i)', 'T1049', 'System Network Connections Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:ps\s+(?:aux|ef|axo)|top\b|htop\b|pstree\b)', 'T1057', 'Process Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:find\s+\/|locate\s+|ls\s+-[laR]+\s+\/|tree\s+\/)', 'T1083', 'File and Directory Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:cat\s+\/etc\/passwd|getent\s+passwd|cut\s+.*\/etc\/passwd|compgen\s+-u)', 'T1087.001', 'Account Discovery: Local Account');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:arp\s+-a|ping\s+-c|nmap\b|masscan\b|zmap\b|cat\s+\/etc\/hosts|nslookup)', 'T1018', 'Remote System Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:groups\b|cat\s+\/etc\/group|getent\s+group|id\s+-[gG])', 'T1069.001', 'Permission Groups Discovery: Local Groups');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:bash\s+-[ci]|sh\s+-c|\/bin\/(?:ba)?sh\b|python[23]?\s+-c|perl\s+-e|ruby\s+-e)', 'T1059.004', 'Command and Scripting Interpreter: Unix Shell');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:crontab|\/etc\/cron|\/var\/spool\/cron)', 'T1053.003', 'Scheduled Task/Job: Cron');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:useradd|adduser|echo\s+.*>>?\s*\/etc\/passwd)', 'T1136.001', 'Create Account: Local Account');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:usermod|\bpasswd\b|chpasswd)', 'T1098', 'Account Manipulation');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:insmod|modprobe|lsmod|rmmod)', 'T1547.006', 'Boot or Logon Autostart: Kernel Modules');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:sudo\s+-[lksi]|sudo\s+su|sudo\s+bash|sudo\s+\/bin\/sh|pkexec)', 'T1548.003', 'Abuse Elevation Control: Sudo');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:history\s+-c|unset\s+HISTFILE|export\s+HISTFILESIZE=0|rm\s+.*\.bash_history|set\s+\+o\s+history)', 'T1070.003', 'Indicator Removal: Clear Command History');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:chmod\s+[0-7]{3,4}|chmod\s+[ugoa]*[+=-][rwxst]+|chown\s+|chattr\s+)', 'T1222.002', 'File and Directory Permissions Modification: Linux');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:iptables\s+-F|ufw\s+disable|systemctl\s+(?:stop|disable)\s+(?:firewalld|iptables|fail2ban|apparmor)|setenforce\s+0)', 'T1562.001', 'Impair Defenses: Disable or Modify Tools');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:wget\s+http|curl\s+(?:-[sOkL]+\s+)?http|tftp\b|ftpget\b)', 'T1105', 'Ingress Tool Transfer');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:rm\s+-rf\s+\/|mkfs\b|dd\s+if=\/dev\/(?:zero|urandom)\s+of=\/|shred\s+)', 'T1485', 'Data Destruction');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:xmrig|minerd|stratum\+tcp|cryptonight|monero|cpuminer|hashrate|pool\.mining|nicehash)', 'T1496', 'Resource Hijacking (Cryptomining)');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:base64\s+(?:-d|--decode)|openssl\s+enc|eval\s*\$\()', 'T1027', 'Obfuscated Files or Information');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:tar\s+[cxz]+|zip\s+|gzip\s+|bzip2\s+|7z\s+a)', 'T1560', 'Archive Collected Data');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:\/dev\/tcp\/|nc\s+.*-e|ncat\b.*-e|socat\b.*exec)', 'T1041', 'Exfiltration Over C2 Channel');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:ssh\s+.*-[DRL]|proxychains|ngrok)', 'T1090', 'Proxy');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:ssh\s+\w+@|sshpass\b|ssh-copy-id)', 'T1021.004', 'Remote Services: SSH');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:ssh-keygen|authorized_keys)', 'T1098.004', 'Account Manipulation: SSH Authorized Keys');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:\/tmp\/|\/dev\/shm\/)', 'T1074.001', 'Data Staged: Local Data Staging');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:screen\b|tmux\b|nohup\b|disown\b)', 'T1036', 'Masquerading (Persistence via Terminal Multiplexer)');
