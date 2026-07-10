-- ============================================================================
--  MIRAGE — Comprehensive ATT&CK Technique Signature Library
-- ============================================================================
--  Each row maps a regex pattern to a MITRE ATT&CK technique ID and name.
--  The analytics pipeline matches every command against these patterns to
--  populate the session_techniques junction table.
--
--  Reference: https://attack.mitre.org/techniques/enterprise/
--
--  Total Signatures: 80+
--  Covers: SSH honeypot commands + HTTP web scanner requests
-- ============================================================================


-- ════════════════════════════════════════════════════════════════════════════
--  SECTION 1: SSH HONEYPOT SIGNATURES (Terminal Command Patterns)
-- ════════════════════════════════════════════════════════════════════════════

-- ── Reconnaissance ──────────────────────────────────────────────────────────

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
('(?:df\s|mount\b|lsblk\b|fdisk\s+-l|blkid\b|cat\s+\/etc\/fstab)', 'T1082.001', 'System Information Discovery: Disk');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:env\b|printenv\b|set\b|export\b|cat\s+.*\.bashrc|cat\s+.*\.profile)', 'T1082.002', 'System Information Discovery: Environment');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:dpkg\s+-l|rpm\s+-qa|apt\s+list|yum\s+list|pacman\s+-Q|pip\s+list|gem\s+list)', 'T1518', 'Software Discovery');

-- ── Credential Access ───────────────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:cat|head|tail|less|more|strings|grep).*\/etc\/(?:passwd|shadow)', 'T1003.008', 'OS Credential Dumping: /etc/passwd & /etc/shadow');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:cat|head|tail|strings|grep).*(?:\.ssh\/|id_rsa|id_ed25519|id_dsa|\.pem\b|\.key\b)', 'T1552.004', 'Unsecured Credentials: Private Keys');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:cat|grep|strings).*(?:\.bash_history|\.mysql_history|\.psql_history|\.wget-hsts|\.lesshst)', 'T1552.003', 'Unsecured Credentials: Bash History');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:cat|grep|strings).*(?:wp-config\.php|config\.php|\.env|database\.yml|settings\.py|application\.properties)', 'T1552.001', 'Unsecured Credentials: Credentials In Files');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:hydra\b|medusa\b|ncrack\b|john\b|hashcat\b|brute)', 'T1110', 'Brute Force');

-- ── Execution ───────────────────────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:bash\s+-[ci]|sh\s+-c|\/bin\/(?:ba)?sh\b|python[23]?\s+-c|perl\s+-e|ruby\s+-e)', 'T1059.004', 'Command and Scripting Interpreter: Unix Shell');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:python[23]?\s+|python[23]?\s+-[cm]|\.py\b)', 'T1059.006', 'Command and Scripting Interpreter: Python');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:perl\s+|\.pl\b|perl\s+-[ew])', 'T1059.005', 'Command and Scripting Interpreter: Perl');

-- ── Persistence ─────────────────────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:crontab|\/etc\/cron|\/var\/spool\/cron)', 'T1053.003', 'Scheduled Task/Job: Cron');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:useradd|adduser|echo\s+.*>>?\s*\/etc\/passwd)', 'T1136.001', 'Create Account: Local Account');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:usermod|\bpasswd\b|chpasswd)', 'T1098', 'Account Manipulation');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:ssh-keygen|authorized_keys)', 'T1098.004', 'Account Manipulation: SSH Authorized Keys');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:insmod|modprobe|lsmod|rmmod)', 'T1547.006', 'Boot or Logon Autostart: Kernel Modules');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:systemctl\s+enable|update-rc\.d|chkconfig\s+.*on|rc\.local)', 'T1543.002', 'Create or Modify System Process: Systemd Service');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:\.bashrc|\.bash_profile|\.profile|\.zshrc|\/etc\/profile)', 'T1546.004', 'Event Triggered Execution: Unix Shell Config Modification');

-- ── Privilege Escalation ────────────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:sudo\s+-[lksi]|sudo\s+su|sudo\s+bash|sudo\s+\/bin\/sh|pkexec)', 'T1548.003', 'Abuse Elevation Control: Sudo');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:find\s+.*-perm\s+.*4000|find\s+.*-perm\s+.*-u=s|find\s+.*suid)', 'T1548.001', 'Abuse Elevation Control: Setuid and Setgid');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:docker\s+run|docker\s+exec|docker\s+.*--privileged|nsenter\b|unshare\b)', 'T1611', 'Escape to Host (Container Escape)');

-- ── Defense Evasion ─────────────────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:history\s+-c|unset\s+HISTFILE|export\s+HISTFILESIZE=0|rm\s+.*\.bash_history|set\s+\+o\s+history)', 'T1070.003', 'Indicator Removal: Clear Command History');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:chmod\s+[0-7]{3,4}|chmod\s+[ugoa]*[+=-][rwxst]+|chown\s+|chattr\s+)', 'T1222.002', 'File and Directory Permissions Modification: Linux');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:iptables\s+-F|ufw\s+disable|systemctl\s+(?:stop|disable)\s+(?:firewalld|iptables|fail2ban|apparmor)|setenforce\s+0)', 'T1562.001', 'Impair Defenses: Disable or Modify Tools');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:base64\s+(?:-d|--decode)|openssl\s+enc|eval\s*\$\()', 'T1027', 'Obfuscated Files or Information');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:rm\s+-rf\s+\/var\/log|truncate\s+.*\/var\/log|echo\s+.*>\s*\/var\/log|cat\s+\/dev\/null\s*>\s*\/var\/log)', 'T1070.002', 'Indicator Removal: Clear Linux System Logs');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:kill\s+-9|killall\b|pkill\b|skill\b)', 'T1489', 'Service Stop');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:mv\s+.*\/usr\/(?:bin|sbin)|cp\s+.*\/usr\/(?:bin|sbin)|ln\s+-s.*\/usr\/(?:bin|sbin))', 'T1036.005', 'Masquerading: Match Legitimate Name or Location');

-- ── Lateral Movement ────────────────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:ssh\s+\w+@|sshpass\b|ssh-copy-id)', 'T1021.004', 'Remote Services: SSH');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:ssh\s+.*-[DRL]|proxychains|ngrok)', 'T1090', 'Proxy');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:scp\s+|rsync\s+|sftp\s+)', 'T1021.004.001', 'Remote Services: SSH File Transfer');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:nmap\s+-[sSUAO]|nmap\s+-p|masscan\s+-p|zmap\s+-p)', 'T1046', 'Network Service Scanning');

-- ── Collection & Exfiltration ───────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:tar\s+[cxz]+|zip\s+|gzip\s+|bzip2\s+|7z\s+a)', 'T1560', 'Archive Collected Data');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:\/dev\/tcp\/|nc\s+.*-e|ncat\b.*-e|socat\b.*exec)', 'T1041', 'Exfiltration Over C2 Channel');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:\/tmp\/|\/dev\/shm\/)', 'T1074.001', 'Data Staged: Local Data Staging');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:screen\b|tmux\b|nohup\b|disown\b)', 'T1036', 'Masquerading (Persistence via Terminal Multiplexer)');

-- ── Command and Control ─────────────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:wget\s+http|curl\s+(?:-[sOkL]+\s+)?http|tftp\b|ftpget\b)', 'T1105', 'Ingress Tool Transfer');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:python.*http\.server|php\s+-S|ruby.*webrick|busybox\s+httpd)', 'T1071.001', 'Application Layer Protocol: Web Protocols');

-- ── Impact ───────────────────────────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:rm\s+-rf\s+\/|mkfs\b|dd\s+if=\/dev\/(?:zero|urandom)\s+of=\/|shred\s+)', 'T1485', 'Data Destruction');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:xmrig|minerd|stratum\+tcp|cryptonight|monero|cpuminer|hashrate|pool\.mining|nicehash)', 'T1496', 'Resource Hijacking (Cryptomining)');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:reboot\b|shutdown\b|halt\b|poweroff\b|init\s+0)', 'T1529', 'System Shutdown/Reboot');


-- ════════════════════════════════════════════════════════════════════════════
--  SECTION 2: HTTP HONEYPOT SIGNATURES (Web Scanner / Bot Request Patterns)
-- ════════════════════════════════════════════════════════════════════════════

-- ── T1595 - Active Scanning (General Web Probes) ────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:login|signin|admin|wp-login|user\/login|administrator)', 'T1595', 'Active Scanning: Web Login Page Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:robots\.txt|sitemap\.xml|crossdomain\.xml|security\.txt|humans\.txt)', 'T1595.002', 'Active Scanning: Vulnerability Scanning (Robots/Sitemap)');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:\.env|\.git\/config|\.git\/HEAD|\.svn\/entries|\.DS_Store|\.htaccess|\.htpasswd)', 'T1595.003', 'Active Scanning: Sensitive File Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:wp-content|wp-includes|wp-json|wp-admin|wp-cron\.php|xmlrpc\.php|wp-config\.php)', 'T1595.002', 'Active Scanning: WordPress Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:license\.txt|readme\.html|readme\.txt|changelog\.txt|CHANGELOG\.md|VERSION)', 'T1595.002', 'Active Scanning: CMS Fingerprinting');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:phpmyadmin|phpMyAdmin|pma|mysql|adminer|dbadmin|myadmin|sql)', 'T1595.002', 'Active Scanning: Database Admin Panel Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:server-status|server-info|status|health|info\.php|phpinfo\.php|test\.php|i\.php)', 'T1595.002', 'Active Scanning: Server Info Disclosure');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:actuator|api\/v[0-9]|swagger|api-docs|graphql|console|debug)', 'T1595.002', 'Active Scanning: API Endpoint Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:config|configuration|settings|setup|install|backup|dump)', 'T1595.002', 'Active Scanning: Config/Setup Page Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:shell|cmd|command|exec|run|terminal|console|webshell|c99|r57)', 'T1595.002', 'Active Scanning: Web Shell Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:\.well-known|cgi-bin|cgi|scripts|fcgi-bin)', 'T1595.002', 'Active Scanning: CGI/Script Directory Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:vendor|node_modules|bower_components|packages|composer)', 'T1595.003', 'Active Scanning: Dependency Exposure');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:telescope|horizon|nova|elfinder|filemanager|ckfinder|tinymce)', 'T1595.002', 'Active Scanning: Framework Tool Discovery');

-- ── T1190 - Exploit Public-Facing Application ───────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:boaform|GponForm|boa|cgi-bin\/luci|goform|formLogin)', 'T1190', 'Exploit Public-Facing Application: Router/IoT Exploit');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:\.\.\/|\.\.\\\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e)', 'T1190', 'Exploit Public-Facing Application: Path Traversal');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:UNION\s+SELECT|OR\s+1=1|AND\s+1=1|DROP\s+TABLE|INSERT\s+INTO|SELECT\s+.*FROM|SLEEP\s*\(|BENCHMARK\s*\()', 'T1190', 'Exploit Public-Facing Application: SQL Injection');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:<script|javascript:|onerror=|onload=|alert\(|prompt\(|confirm\(|document\.cookie)', 'T1190', 'Exploit Public-Facing Application: XSS Attempt');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:eval\(|exec\(|system\(|passthru\(|shell_exec\(|popen\(|proc_open\()', 'T1190', 'Exploit Public-Facing Application: Remote Code Execution');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:ThinkPHP|think\\\\|invokefunction|index\/\\\\think)', 'T1190', 'Exploit Public-Facing Application: ThinkPHP RCE');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:Jndi|jndi:|log4j|Log4Shell|\$\{jndi)', 'T1190', 'Exploit Public-Facing Application: Log4Shell (CVE-2021-44228)');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:\.asp|\.aspx|\.jsp|\.do|\.action|struts|\.cgi)(?:\?|$)', 'T1190', 'Exploit Public-Facing Application: Legacy Web App Probe');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:solr|jenkins|jmx-console|manager\/html|axis2|web-console)', 'T1190', 'Exploit Public-Facing Application: Java App Server Discovery');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:remote\/login|sslvpn|dana-na|global-protect|vpn|portal)', 'T1190', 'Exploit Public-Facing Application: VPN/Gateway Probe');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:ecp|owa|autodiscover|exchange|aspnet_client|rpc)', 'T1190', 'Exploit Public-Facing Application: Exchange Server Probe');

-- ── T1133 - External Remote Services ────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('GET\s+\/(?:remote|rdweb|Citrix|vmware|esxi|vcenter)', 'T1133', 'External Remote Services: Remote Access Discovery');

-- ── T1592 - Gather Victim Host Information ──────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:OPTIONS\s+\/|HEAD\s+\/|TRACE\s+\/|PROPFIND\s+\/)', 'T1592', 'Gather Victim Host Information: HTTP Method Probing');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('^(?:HEAD|POST|PUT|DELETE|OPTIONS)\b', 'T1592.004', 'Gather Victim Network Information: Client Configurations');

-- ── Generic Protocol Handshakes & Reconnaissance ────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('^GET\b', 'T1592.004', 'Gather Victim Network Information: Client Configurations');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('^(?:AUTH\s+|USER\s+|PASS\s+)', 'T1592.004', 'Gather Victim Network Information: Client Configurations');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('^(?:RFB|security_type|MGLNDD)', 'T1592.004', 'Gather Victim Network Information: Client Configurations');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('^(?:EHLO|HELO|STARTTLS|QUIT|MAIL FROM|RCPT TO)\b', 'T1592.004', 'Gather Victim Network Information: Client Configurations');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('^DATA\b', 'T1048', 'Exfiltration Over Alternative Protocol');

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('^$', 'T1592.004', 'Gather Victim Network Information: Client Configurations');


-- ── T1078 - Valid Accounts ──────────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('POST\s+\/(?:login|signin|authenticate|auth|session|api\/login|api\/auth|j_security_check)', 'T1078', 'Valid Accounts: Credential Stuffing via Web Login');

-- ── T1498 - Network Denial of Service ───────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('(?:GET\s+\/\s+HTTP.*\r?\n(?:.*\r?\n)*?User-Agent:\s*$|GET\s+\/\s+HTTP.*\r?\n(?:.*\r?\n)*?User-Agent:\s*-)', 'T1498', 'Network Denial of Service: Empty User-Agent Flood');

-- ── T1110 - Brute Force (Honeypot Logins) ──────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('LOGIN FAILED:', 'T1110.001', 'Brute Force: Password Guessing');

-- ── Generic Fallbacks ─────────────────────────────────────────────────────────

INSERT OR IGNORE INTO technique_signatures (pattern, attack_technique_id, technique_name) VALUES
('^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\/', 'T1595.002', 'Active Scanning: Generic Web Probe');


