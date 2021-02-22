export const PRIVILEGE_ESCALATION_DETAILS = [
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
    "technique_description": "Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.  <br /><br />Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. <br /><br />An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.<br /><br />",
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
    "technique_description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)<br /><br />Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).<br /><br />",
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
    "technique_description": "Adversaries may exploit software vulnerabilities in an attempt to collect elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.<br /><br />When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This may be a necessary step for an adversary compromising a endpoint system that has been properly configured and limits other privilege escalation methods.<br /><br />",
    "technique_references": []
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
    "technique_description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. (Citation: TechNet Services) On macOS, launchd processes known as [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) and [Launch Agent](https://attack.mitre.org/techniques/T1543/001) are run to finish system initialization and load user specific parameters.(Citation: AppleDocs Launch Agent Daemons) <br /><br />Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.  <br /><br />Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges. (Citation: OSX Malware Detection).  <br /><br />",
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
    "technique_description": "Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. <br /><br />Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.(Citation: FireEye WMI 2015)(Citation: Malware Persistence on OS X)(Citation: amnesia malware)<br /><br />Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges. <br /><br />",
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
    "technique_description": "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux Kernel Programming)  These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.<br /><br />Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.<br /><br />",
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
    "technique_description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.<br /><br />",
    "technique_references": []
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
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.<br /><br />There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating system locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.<br /><br />",
    "technique_references": [
      {
        "source_name": "Autoruns for Windows",
        "url": "https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns",
        "description": "Mark Russinovich. (2019, June 28). Autoruns for Windows v13.96. Retrieved March 13, 2020.",
        "external_id": "none"
      }
    ]
  }
]
