 [
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
    "technique_description": "Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain.<br /><br />",
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
    "technique_description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) can also be used externally.<br /><br />Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.<br /><br />",
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
    "technique_description": "Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.<br /><br />Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.<br /><br />",
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
    "technique_description": "Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins.<br /><br />A variety of features have been discovered in Outlook that can be abused to obtain persistence, such as Outlook rules, forms, and Home Page.(Citation: SensePost Ruler GitHub) These persistence mechanisms can work within Outlook or be used through Office 365.(Citation: TechNet O365 Outlook Rules)<br /><br />",
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
    "technique_description": "Adversaries may abuse Internet browser extensions to establish persistence access to victim systems. Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers. They can be installed directly or through a browser's app store and generally have access and permissions to everything that the browser can access. (Citation: Wikipedia Browser Extension) (Citation: Chrome Extensions Definition)<br /><br />Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system. Security can be limited on browser app stores so it may not be difficult for malicious extensions to defeat automated scanners. (Citation: Malicious Chrome Extension Numbers) Once the extension is installed, it can browse to websites in the background, (Citation: Chrome Extension Crypto Miner) (Citation: ICEBRG Chrome Extensions) steal all information that a user enters into a browser (including credentials) (Citation: Banker Google Chrome Extension Steals Creds) (Citation: Catch All Chrome Extension) and be used as an installer for a RAT for persistence.<br /><br />There have also been instances of botnets using a persistent backdoor through malicious Chrome extensions. (Citation: Stantinko Botnet) There have also been similar examples of extensions being used for command & control  (Citation: Chrome Extension C2 Malware).<br /><br />",
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
    "technique_description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.<br /><br />",
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
    "technique_description": "Adversaries may implant cloud container images with malicious code to establish persistence. Amazon Web Service (AWS) Amazon Machine Images (AMI), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019)<br /><br />A tool has been developed to facilitate planting backdoors in cloud container images.(Citation: Rhino Labs Cloud Backdoor September 2019) If an attacker has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a [Web Shell](https://attack.mitre.org/techniques/T1505/003).(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019) Adversaries may also implant Docker images that may be inadvertently used in cloud deployments, which has been reported in some instances of cryptomining botnets.(Citation: ATT Cybersecurity Cryptocurrency Attacks on Cloud) <br /><br />",
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
    "technique_description": "Adversaries may modify client software binaries to establish persistent access to systems. Client software enables users to access services provided by a server. Common client software types are SSH clients, FTP clients, email clients, and web browsers.<br /><br />Adversaries may make modifications to client software binaries to carry out malicious tasks when those applications are in use. For example, an adversary may copy source code for the client software, add a backdoor, compile for the target, and replace the legitimate application binary (or support files) with the backdoored one. Since these applications may be routinely executed by the user, the adversary can leverage this for persistent access to the host.<br /><br />",
    "technique_references": []
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
