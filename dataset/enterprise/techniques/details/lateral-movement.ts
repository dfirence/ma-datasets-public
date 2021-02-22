 [
  {
    "id": "attack-pattern--54a649ff-439a-41a4-9856-8d144a2551ba",
    "platform": "linux|macos|windows",
    "tid": "T1021",
    "technique": "Remote Services",
    "tactic": "lateral-movement",
    "datasources": "api-monitoring|authentication-logs|dll-monitoring|file-monitoring|netflow-enclave-netflow|network-protocol-analysis|packet-capture|powershell-logs|process-command-line-parameters|process-monitoring|process-use-of-network|windows-event-logs|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1021.001",
      "T1021.002",
      "T1021.003",
      "T1021.004",
      "T1021.005",
      "T1021.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.<br /><br />In an enterprise environment, servers and workstations can be organized into domains. Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network. If an adversary is able to obtain a set of valid domain credentials, they could login to many different machines using remote access protocols such as secure shell (SSH) or remote desktop protocol (RDP).(Citation: SSH Secure Shell)(Citation: TechNet Remote Desktop Services)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/555.html",
        "description": "none",
        "external_id": "CAPEC-555"
      },
      {
        "source_name": "SSH Secure Shell",
        "url": "https://www.ssh.com/ssh",
        "description": "SSH.COM. (n.d.). SSH (Secure Shell). Retrieved March 23, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Remote Desktop Services",
        "url": "https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx",
        "description": "Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--92a78814-b191-47ca-909c-1ccfe3777414",
    "platform": "linux|macos|windows",
    "tid": "T1072",
    "technique": "Software Deployment Tools",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs|binary-file-metadata|file-monitoring|process-monitoring|process-use-of-network|third-party-application-logs|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.).<br /><br />Access to a third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.<br /><br />The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform it's intended purpose.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/187.html",
        "description": "none",
        "external_id": "CAPEC-187"
      }
    ]
  },
  {
    "id": "attack-pattern--246fd3c7-f5e3-466d-8787-4c13d9e3b61c",
    "platform": "windows",
    "tid": "T1080",
    "technique": "Taint Shared Content",
    "tactic": "lateral-movement",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally.<br /><br />A directory share pivot is a variation on this technique that uses several other techniques to propagate malware when users access a shared network directory. It uses [Shortcut Modification](https://attack.mitre.org/techniques/T1547/009) of directory .LNK files that use [Masquerading](https://attack.mitre.org/techniques/T1036) to look like the real directories, which are hidden through [Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001). The malicious .LNK-based directories have an embedded command that executes the hidden malware file in the directory and then opens the real intended directory so that the user's expected action still occurs. When used with frequently used network directories, the technique may result in frequent reinfections and broad access to systems and potentially to new and higher privileged accounts. (Citation: Retwin Directory Share Pivot)<br /><br />Adversaries may also compromise shared network directories through binary infections by appending or prepending its code to the healthy binary on the shared network directory. The malware may modify the original entry point (OEP) of the healthy binary to ensure that it is executed before the legitimate code. The infection could continue to spread via the newly infected file when it is executed by a remote system. These infections may target both binary and non-binary formats that end with extensions including, but not limited to, .EXE, .DLL, .SCR, .BAT, and/or .VBS.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/562.html",
        "description": "none",
        "external_id": "CAPEC-562"
      },
      {
        "source_name": "Retwin Directory Share Pivot",
        "url": "https://rewtin.blogspot.ch/2017/11/abusing-user-shares-for-efficient.html",
        "description": "Routin, D. (2017, November 13). Abusing network shares for efficient lateral movements and privesc (DirSharePivot). Retrieved April 12, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3b744087-9945-4a6f-91e8-9dbceda417a4",
    "platform": "windows",
    "tid": "T1091",
    "technique": "Replication Through Removable Media",
    "tactic": "lateral-movement",
    "datasources": "data-loss-prevention|file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--9db0cf3a-a3c9-4012-8268-123b9db6fd82",
    "platform": "linux|windows|macos",
    "tid": "T1210",
    "technique": "Exploitation of Remote Services",
    "tactic": "lateral-movement",
    "datasources": "file-monitoring|process-monitoring|windows-error-reporting",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.<br /><br />An adversary may need to determine if the remote system is in a vulnerable state, which may be done through [Network Service Scanning](https://attack.mitre.org/techniques/T1046) or other Discovery methods looking for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities,  or security software that may be used to detect or contain remote exploitation. Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk if they provide an advantage or access to additional resources.<br /><br />There are several well-known vulnerabilities that exist in common services such as SMB (Citation: CIS Multiple SMB Vulnerabilities) and RDP (Citation: NVD CVE-2017-0176) as well as applications that may be used within internal networks such as MySQL (Citation: NVD CVE-2016-6662) and web server services. (Citation: NVD CVE-2014-7169)<br /><br />Depending on the permissions level of the vulnerable remote service an adversary may achieve [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) as a result of lateral movement exploitation as well.<br /><br />",
    "technique_references": [
      {
        "source_name": "CIS Multiple SMB Vulnerabilities",
        "url": "https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/",
        "description": "CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "NVD CVE-2017-0176",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0176",
        "description": "National Vulnerability Database. (2017, June 22). CVE-2017-0176 Detail. Retrieved April 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "NVD CVE-2016-6662",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-6662",
        "description": "National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "NVD CVE-2014-7169",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-7169",
        "description": "National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--9e7452df-5144-4b6e-b04a-b66dd4016747",
    "platform": "windows|macos|linux|office-365|saas",
    "tid": "T1534",
    "technique": "Internal Spearphishing",
    "tactic": "lateral-movement",
    "datasources": "anti-virus|dns-records|file-monitoring|mail-server|office-365-trace-logs|ssl-tls-inspection|web-proxy",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization after they already have access to accounts or systems within the environment. Internal spearphishing is multi-staged attack where an email account is owned either by controlling the user's device with previously installed malware or by compromising the account credentials of the user. Adversaries attempt to take advantage of a trusted internal account to increase the likelihood of tricking the target into falling for the phish attempt.(Citation: Trend Micro When Phishing Starts from the Inside 2017)<br /><br />Adversaries may leverage [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) or [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through [Input Capture](https://attack.mitre.org/techniques/T1056) on sites that mimic email login interfaces.<br /><br />There have been notable incidents where internal spearphishing has been used. The Eye Pyramid campaign used phishing emails with malicious attachments for lateral movement between victims, compromising nearly 18,000 email accounts in the process.(Citation: Trend Micro When Phishing Starts from the Inside 2017) The Syrian Electronic Army (SEA) compromised email accounts at the Financial Times (FT) to steal additional account credentials. Once FT learned of the attack and began warning employees of the threat, the SEA sent phishing emails mimicking the Financial Times IT department and were able to compromise even more users.(Citation: THE FINANCIAL TIMES LTD 2019.)<br /><br />",
    "technique_references": [
      {
        "source_name": "Trend Micro When Phishing Starts from the Inside 2017",
        "url": "https://blog.trendmicro.com/phishing-starts-inside/",
        "description": "Chris Taylor. (2017, October 5). When Phishing Starts from the Inside. Retrieved October 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "THE FINANCIAL TIMES LTD 2019.",
        "url": "https://labs.ft.com/2013/05/a-sobering-day/?mhq5j=e6",
        "description": "THE FINANCIAL TIMES. (2019, September 2). A sobering day. Retrieved October 8, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--51a14c76-dd3b-440b-9c20-2bf91d25a814",
    "platform": "windows|office-365|saas",
    "tid": "T1550",
    "technique": "Use Alternate Authentication Material",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs|oauth-audit-logs|office-365-audit-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1550.001",
      "T1550.002",
      "T1550.003",
      "T1550.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls. <br /><br />Authentication processes generally require a valid identity (e.g., username) along with one or more authentication factors (e.g., password, pin, physical smart card, token generator, etc.). Alternate authentication material is legitimately generated by systems after a user or application successfully authenticates by providing a valid identity and the required authentication factor(s). Alternate authentication material may also be generated during the identity creation process.(Citation: NIST Authentication)(Citation: NIST MFA)<br /><br />Caching alternate authentication material allows the system to verify an identity has successfully authenticated without asking the user to reenter authentication factor(s). Because the alternate authentication must be maintained by the system—either in memory or on disk—it may be at risk of being stolen through [Credential Access](https://attack.mitre.org/tactics/TA0006) techniques. By stealing alternate authentication material, adversaries are able to bypass system access controls and authenticate to systems without knowing the plaintext password or any additional authentication factors.<br /><br />",
    "technique_references": [
      {
        "source_name": "NIST Authentication",
        "url": "https://csrc.nist.gov/glossary/term/authentication",
        "description": "NIST. (n.d.). Authentication. Retrieved January 30, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "NIST MFA",
        "url": "https://csrc.nist.gov/glossary/term/Multi_Factor-Authentication",
        "description": "NIST. (n.d.). Multi-Factor Authentication (MFA). Retrieved January 30, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Audit Policy",
        "url": "https://technet.microsoft.com/en-us/library/dn487457.aspx",
        "description": "Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--5b0ad6f8-6a16-4966-a4ef-d09ea6e2a9f5",
    "platform": "linux|macos|windows",
    "tid": "T1563",
    "technique": "Remote Service Session Hijacking",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs|netflow-enclave-netflow|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1563.001",
      "T1563.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.<br /><br />Adversaries may commandeer these sessions to carry out actions on remote systems. [Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563) differs from use of [Remote Services](https://attack.mitre.org/techniques/T1021) because it hijacks an existing session rather than creating a new session using [Valid Accounts](https://attack.mitre.org/techniques/T1078).(Citation: RDP Hijacking Medium)(Citation: Breach Post-mortem SSH Hijack)<br /><br />",
    "technique_references": [
      {
        "source_name": "RDP Hijacking Medium",
        "url": "https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6",
        "description": "Beaumont, K. (2017, March 19). RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation. Retrieved December 11, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Breach Post-mortem SSH Hijack",
        "url": "https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident",
        "description": "Hodgson, M. (2019, May 8). Post-mortem and remediations for Apr 11 security incident. Retrieved February 17, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--bf90d72c-c00b-45e3-b3aa-68560560d4c5",
    "platform": "linux|macos|windows",
    "tid": "T1570",
    "technique": "Lateral Tool Transfer",
    "tactic": "lateral-movement",
    "datasources": "file-monitoring|netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-command-line-parameters|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may transfer tools or other files between systems in a compromised environment. Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Adversaries may copy files laterally between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) or [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001). Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.<br /><br />",
    "technique_references": []
  }
]
