export const DEFENSE_EVASION_DETAILS = [
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
    "technique_description": "Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools. (Citation: Hakobyan 2009)<br /><br />Utilities, such as NinjaCopy, exist to perform these actions in PowerShell. (Citation: Github PowerSploit Ninjacopy)<br /><br />",
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
    "technique_description": "Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information. (Citation: Symantec Windows Rootkits) <br /><br />Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a hypervisor, Master Boot Record, or [System Firmware](https://attack.mitre.org/techniques/T1542/001). (Citation: Wikipedia Rootkit) Rootkits have been seen for Windows, Linux, and Mac OS X systems. (Citation: CrowdStrike Linux Rootkit) (Citation: BlackHat Mac OSX Rootkit)<br /><br />",
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
    "technique_description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses. <br /><br />Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) for [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used compressed or archived scripts, such as JavaScript. <br /><br />Portions of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)<br /><br />Adversaries may also obfuscate commands executed from payloads or directly via a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059). Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detections and application control mechanisms. (Citation: FireEye Obfuscation June 2017) (Citation: FireEye Revoke-Obfuscation July 2017)(Citation: PaloAlto EncodedCommand March 2017) <br /><br />",
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
    "technique_description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.<br /><br />Renaming abusable system utilities to evade security monitoring is also a form of [Masquerading](https://attack.mitre.org/techniques/T1036).(Citation: LOLBAS Main Site)<br /><br />",
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
    "technique_description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. <br /><br />There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific. <br /><br />More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel. <br /><br />",
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
    "technique_description": "Adversaries may delete or alter generated artifacts on a host system, including logs or captured files such as quarantined malware. Locations and format of logs are platform or product-specific, however standard operating system logs are captured as Windows events or Linux/macOS files such as [Bash History](https://attack.mitre.org/techniques/T1139) and /var/log/*.<br /><br />These actions may interfere with event collection, reporting, or other notifications used to detect intrusion activity. This that may compromise the integrity of security solutions by causing notable events to go unreported. This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred.<br /><br />",
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
    "technique_description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.<br /><br />The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise. (Citation: TechNet Credential Theft)<br /><br />",
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
    "technique_description": "Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.<br /><br />Access to specific areas of the Registry depends on account permissions, some requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification. (Citation: Microsoft Reg) Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API.<br /><br />Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API. (Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence. (Citation: TrendMicro POWELIKS AUG 2014) (Citation: SpectorOps Hiding Reg Jul 2017)<br /><br />The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system. (Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) for RPC communication.<br /><br />",
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
    "technique_description": "Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering.(Citation: engima0x3 DNX Bypass)(Citation: engima0x3 RCSI Bypass)(Citation: Exploit Monday WinDbg)(Citation: LOLBAS Tracker) These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.<br /><br />",
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
    "technique_description": "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.<br /><br />An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. [Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001)) or used to spawn a new process (i.e. [Create Process with Token](https://attack.mitre.org/techniques/T1134/002)). An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.(Citation: Pentestlab Token Manipulation)<br /><br />Any standard user can use the <code>runas</code> command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens.<br /><br />",
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
    "technique_description": "Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.<br /><br />One such example is use of [certutil](https://attack.mitre.org/software/S0160) to decode a remote access tool portable executable file that has been hidden inside a certificate file. (Citation: Malwarebytes Targeted Attack against Saudi Arabia) Another example is using the Windows <code>copy /b</code> command to reassemble binary fragments into a malicious payload. (Citation: Carbon Black Obfuscation Sept 2016)<br /><br />Sometimes a user's action may be required to open it for deobfuscation or decryption as part of [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke November 2016)<br /><br />",
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
    "technique_description": "Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM). (Citation: Microsoft COM) (Citation: Microsoft BITS) BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.<br /><br />The interface to create and manage BITS jobs is accessible through [PowerShell](https://attack.mitre.org/techniques/T1059/001)  (Citation: Microsoft BITS) and the [BITSAdmin](https://attack.mitre.org/software/S0190) tool. (Citation: Microsoft BITSAdmin)<br /><br />Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. (Citation: CTU BITS Malware June 2016) (Citation: Mondok Windows PiggyBack BITS May 2007) (Citation: Symantec BITS May 2007) BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots). (Citation: PaloAlto UBoatRAT Nov 2017) (Citation: CTU BITS Malware June 2016)<br /><br />BITS upload functionalities can also be used to perform [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048). (Citation: CTU BITS Malware June 2016)<br /><br />",
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
    "technique_description": "Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking [cmd](https://attack.mitre.org/software/S0106). For example, [Forfiles](https://attack.mitre.org/software/S0193), the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), Run window, or via scripts. (Citation: VectorSec ForFiles Aug 2017) (Citation: Evi1cg Forfiles Nov 2017)<br /><br />Adversaries may abuse these features for [Defense Evasion](https://attack.mitre.org/tactics/TA0005), specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of [cmd](https://attack.mitre.org/software/S0106) or file extensions more commonly associated with malicious payloads.<br /><br />",
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
    "technique_description": "Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. [Port Knocking](https://attack.mitre.org/techniques/T1205/001)), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.<br /><br />Adversaries may also communicate with an already open port, but the service listening on that port will only respond to commands or trigger other malicious functionality if passed the appropriate magic value(s).<br /><br />The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.<br /><br />On network devices, adversaries may use crafted packets to enable [Network Device Authentication](https://attack.mitre.org/techniques/T1556/004) for standard services offered by the device such as telnet.  Such signaling may also be used to open a closed service port such as telnet, or to trigger module modification of malware implants on the device, adding, removing, or changing malicious capabilities.(Citation: Cisco Synful Knock Evolution) (Citation: FireEye - Synful Knock) (Citation: Cisco Blog Legacy Device Attacks)  To enable this traffic signaling on embedded devices, adversaries must first achieve and leverage [Patch System Image](https://attack.mitre.org/techniques/T1601/001) due to the monolithic nature of the architecture.<br /><br />",
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
    "technique_description": "Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC). DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC. (Citation: DCShadow Blog) Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys.<br /><br />Registering a rogue DC involves creating a new server and nTDSDSA objects in the Configuration partition of the AD schema, which requires Administrator privileges (either Domain or local to the DC) or the KRBTGT hash. (Citation: Adsecurity Mimikatz Guide)<br /><br />This technique may bypass system logging and security monitors such as security information and event management (SIEM) products (since actions taken on a rogue DC may not be reported to these sensors). (Citation: DCShadow Blog) The technique may also be used to alter and delete replication and other associated metadata to obstruct forensic analysis. Adversaries may also utilize this technique to perform [SID-History Injection](https://attack.mitre.org/techniques/T1178) and/or manipulate AD objects (such as accounts, access control lists, schemas) to establish backdoors for Persistence. (Citation: DCShadow Blog)<br /><br />",
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
    "technique_description": "Adversaries may exploit a system or application vulnerability to bypass security features. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Vulnerabilities may exist in defensive security software that can be used to disable or circumvent them.<br /><br />Adversaries may have prior knowledge through reconnaissance that security software exists within an environment or they may perform checks during or shortly after the system is compromised for [Security Software Discovery](https://attack.mitre.org/techniques/T1518/001). The security software will likely be targeted directly for exploitation. There are examples of antivirus software being targeted by persistent threat groups to avoid detection.<br /><br />",
    "technique_references": []
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
    "technique_description": "Adversaries may use scripts signed with trusted certificates to proxy execution of malicious files. Several Microsoft signed scripts that are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems.(Citation: GitHub Ultimate AppLocker Bypass List)<br /><br />",
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
    "technique_description": "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries. Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files.<br /><br />",
    "technique_references": []
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
    "technique_description": "Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. To support complex operations, the XSL standard includes support for embedded scripting in various languages. (Citation: Microsoft XSLT Script Mar 2017)<br /><br />Adversaries may abuse this functionality to execute arbitrary files while potentially bypassing application control. Similar to [Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127), the Microsoft common line transformation utility binary (msxsl.exe) (Citation: Microsoft msxsl.exe) can be installed and used to execute malicious JavaScript embedded within local or remote (URL referenced) XSL files. (Citation: Penetration Testing Lab MSXSL July 2017) Since msxsl.exe is not installed by default, an adversary will likely need to package it with dropped files. (Citation: Reaqta MSXSL Spearphishing MAR 2018) Msxsl.exe takes two main arguments, an XML source file and an XSL stylesheet. Since the XSL file is valid XML, the adversary may call the same XSL file twice. When using msxsl.exe adversaries may also give the XML/XSL files an arbitrary file extension.(Citation: XSL Bypass Mar 2019)<br /><br />Command-line examples:(Citation: Penetration Testing Lab MSXSL July 2017)(Citation: XSL Bypass Mar 2019)<br /><br />* <code>msxsl.exe customers[.]xml script[.]xsl</code><br /><br />* <code>msxsl.exe script[.]xsl script[.]xsl</code><br /><br />* <code>msxsl.exe script[.]jpeg script[.]jpeg</code><br /><br />Another variation of this technique, dubbed “Squiblytwo”, involves using [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) to invoke JScript or VBScript within an XSL file.(Citation: LOLBAS Wmic) This technique can also execute local/remote scripts and, similar to its [Regsvr32](https://attack.mitre.org/techniques/T1117)/ \"Squiblydoo\" counterpart, leverages a trusted, built-in Windows tool. Adversaries may abuse any alias in [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) provided they utilize the /FORMAT switch.(Citation: XSL Bypass Mar 2019)<br /><br />Command-line examples:(Citation: XSL Bypass Mar 2019)(Citation: LOLBAS Wmic)<br /><br />* Local File: <code>wmic process list /FORMAT:evil[.]xsl</code><br /><br />* Remote File: <code>wmic os get /FORMAT:”https[:]//example[.]com/evil[.]xsl”</code><br /><br />",
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
    "technique_description": "Adversaries may create or modify references in Office document templates to conceal malicious code or force authentication attempts. Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt). OOXML files are packed together ZIP archives compromised of various XML files, referred to as parts, containing properties that collectively define how a document is rendered. (Citation: Microsoft Open XML July 2017)<br /><br />Properties within parts may reference shared public resources accessed via online URLs. For example, template properties reference a file, serving as a pre-formatted document blueprint, that is fetched when the document is loaded.<br /><br />Adversaries may abuse this technology to initially conceal malicious code to be executed via documents. Template references injected into a document may enable malicious payloads to be fetched and executed when the document is loaded. (Citation: SANS Brian Wiltse Template Injection) These documents can be delivered via other techniques such as [Phishing](https://attack.mitre.org/techniques/T1566) and/or [Taint Shared Content](https://attack.mitre.org/techniques/T1080) and may evade static detections since no typical indicators (VBA macro, script, etc.) are present until after the malicious payload is fetched. (Citation: Redxorblue Remote Template Injection) Examples have been seen in the wild where template injection was used to load malicious code containing an exploit. (Citation: MalwareBytes Template Injection OCT 2017)<br /><br />This technique may also enable [Forced Authentication](https://attack.mitre.org/techniques/T1187) by injecting a SMB/HTTPS (or other credential prompting) URL and triggering an authentication attempt. (Citation: Anomali Template Injection MAR 2018) (Citation: Talos Template Injection July 2017) (Citation: ryhanson phishery SEPT 2016)<br /><br />",
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
    "technique_description": "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).<br /><br />Modifications may include changing specific access rights, which may require taking ownership of a file or directory and/or elevated permissions depending on the file or directory’s existing permissions. This may enable malicious activity such as modifying, replacing, or deleting specific files or directories. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), [Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037), [.bash_profile and .bashrc](https://attack.mitre.org/techniques/T1546/004), or tainting/hijacking other instrumental binary/configuration files via [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574).<br /><br />",
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
    "technique_description": "Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign.(Citation: FireEye Kevin Mandia Guardrails) Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses.(Citation: FireEye Outlook Dec 2019)<br /><br />Guardrails can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This use of guardrails is distinct from typical [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497). While use of [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) may involve checking for known sandbox values and continuing with execution only if there is no match, the use of guardrails will involve checking for an expected target-specific value and only continuing with execution if there is such a match.<br /><br />",
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
    "technique_description": "Adversaries may modify the configuration settings of a domain to evade defenses and/or escalate privileges in domain environments. Domains provide a centralized means of managing how computer resources (ex: computers, user accounts) can act, and interact with each other, on a network. The policy of the domain also includes configuration settings that may apply between domains in a multi-domain/forest environment. Modifications to domain settings may include altering domain Group Policy Objects (GPOs) or changing trust settings for domains, including federation trusts.<br /><br />With sufficient permissions, adversaries can modify domain policy settings. Since domain configuration settings control many of the interactions within the Active Directory (AD) environment, there are a great number of potential attacks that can stem from this abuse. Examples of such abuse include modifying GPOs to push a malicious [Scheduled Task](https://attack.mitre.org/techniques/T1053/005) to computers throughout the domain environment(Citation: ADSecurity GPO Persistence 2016)(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions) or modifying domain trusts to include an adversary controlled domain where they can control access tokens that will subsequently be accepted by victim domain resources.(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks) Adversaries can also change configuration settings within the AD environment to implement a [Rogue Domain Controller](https://attack.mitre.org/techniques/T1207).<br /><br />Adversaries may temporarily modify domain policy, carry out a malicious action(s), and then revert the change to remove suspicious indicators.<br /><br />",
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
    "technique_description": "Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors. <br /><br />Adversaries may use several methods to accomplish [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in an analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox.(Citation: Unit 42 Pirpi July 2015)<br /><br />",
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
    "technique_description": "Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure.<br /><br />Cloud service providers often provide infrastructure throughout the world in order to improve performance, provide redundancy, and allow customers to meet compliance requirements. Oftentimes, a customer will only use a subset of the available regions and may not actively monitor other regions. If an adversary creates resources in an unused region, they may be able to operate undetected.<br /><br />A variation on this behavior takes advantage of differences in functionality across cloud regions. An adversary could utilize regions which do not support advanced detection services in order to avoid detection of their activity. For example, AWS GuardDuty is not supported in every region.(Citation: AWS Region Service Table)<br /><br />An example of adversary use of unused AWS regions is to mine cryptocurrency through [Resource Hijacking](https://attack.mitre.org/techniques/T1496), which can cost organizations substantial amounts of money over time depending on the processing power used.(Citation: CloudSploit - Unused AWS Regions)<br /><br />",
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
    "technique_description": "Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.(Citation: Wikipedia Booting)<br /><br />Adversaries may overwrite data in boot drivers or firmware such as BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) to persist on systems at a layer below the operating system. This can be particularly difficult to detect as malware at this level will not be detected by host software-based defenses.<br /><br />",
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
    "technique_description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.<br /><br />",
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
    "technique_description": "Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.<br /><br />Adversaries may attempt to subvert these trust mechanisms. The method adversaries use will depend on the specific mechanism they seek to subvert. Adversaries may conduct [File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222) or [Modify Registry](https://attack.mitre.org/techniques/T1112) in support of subverting these controls.(Citation: SpectorOps Subverting Trust Sept 2017) Adversaries may also create or steal code signing certificates to acquire trust on target systems.(Citation: Securelist Digital Certificates)(Citation: Symantec Digital Certificates) <br /><br />",
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
    "technique_description": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows or pluggable authentication modules (PAM) on Unix-based systems, responsible for gathering, storing, and validating credentials. <br /><br />Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. <br /><br />",
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
    "technique_description": "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.<br /><br />Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components.<br /><br />",
    "technique_references": []
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
    "technique_description": "Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection.(Citation: Sofacy Komplex Trojan)(Citation: Cybereason OSX Pirrit)(Citation: MalwareBytes ADS July 2015)<br /><br />Adversaries may also attempt to hide artifacts associated with malicious behavior by creating computing regions that are isolated from common security instrumentation, such as through the use of virtualization technology.(Citation: Sophos Ragnar May 2020)<br /><br />",
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
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.<br /><br />There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.<br /><br />",
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
    "technique_description": "An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses. A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots.<br /><br />Permissions gained from the modification of infrastructure components may bypass restrictions that prevent access to existing infrastructure. Modifying infrastructure components may also allow an adversary to evade detection and remove evidence of their presence.(Citation: Mandiant M-Trends 2020)<br /><br />",
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
    "technique_description": "Adversaries may bridge network boundaries by compromising perimeter network devices. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.<br /><br />Devices such as routers and firewalls can be used to create boundaries between trusted and untrusted networks.  They achieve this by restricting traffic types to enforce organizational policy in an attempt to reduce the risk inherent in such connections.  Restriction of traffic can be achieved by prohibiting IP addresses, layer 4 protocol ports, or through deep packet inspection to identify applications.  To participate with the rest of the network, these devices can be directly addressable or transparent, but their mode of operation has no bearing on how the adversary can bypass them when compromised.<br /><br />When an adversary takes control of such a boundary device, they can bypass its policy enforcement to pass normally prohibited traffic across the trust boundary between the two separated networks without hinderance.  By achieving sufficient rights on the device, an adversary can reconfigure the device to allow the traffic they want, allowing them to then further achieve goals such as command and control via [Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003) or exfiltration of data via [Traffic Duplication](https://attack.mitre.org/techniques/T1020/001).  In the cases where a border device separates two separate organizations, the adversary can also facilitate lateral movement into new victim environments.<br /><br />",
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
    "technique_description": "Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications. (Citation: Cisco Synful Knock Evolution)<br /><br />Encryption can be used to protect transmitted network traffic to maintain its confidentiality (protect against unauthorized disclosure) and integrity (protect against unauthorized changes). Encryption ciphers are used to convert a plaintext message to ciphertext and can be computationally intensive to decipher without the associated decryption key. Typically, longer keys increase the cost of cryptanalysis, or decryption without the key.<br /><br />Adversaries can compromise and manipulate devices that perform encryption of network traffic. For example, through behaviors such as [Modify System Image](https://attack.mitre.org/techniques/T1601), [Reduce Key Space](https://attack.mitre.org/techniques/T1600/001), and [Disable Crypto Hardware](https://attack.mitre.org/techniques/T1600/002), an adversary can negatively effect and/or eliminate a device’s ability to securely encrypt network traffic. This poses a greater risk of unauthorized disclosure and may help facilitate data manipulation, Credential Access, or Collection efforts. (Citation: Cisco Blog Legacy Device Attacks)<br /><br />",
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
    "technique_description": "Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves.  On such devices, the operating systems are typically monolithic and most of the device functionality and capabilities are contained within a single file.<br /><br />To change the operating system, the adversary typically only needs to affect this one file, replacing or modifying it.  This can either be done live in memory during system runtime for immediate effect, or in storage to implement the change on the next boot of the network device.<br /><br />",
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
  }
]
