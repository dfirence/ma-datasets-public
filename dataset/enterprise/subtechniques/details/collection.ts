export const COLLECTION_SUBTECHNIQUE_DETAILS = [
  {
    "id": "attack-pattern--09a60ea3-a8d1-4ae5-976e-5783248b72a4",
    "platform": "windows|macos|linux|network",
    "tid": "T1056.001",
    "technique": "Keylogging",
    "tactic": "collection",
    "datasources": "api-monitoring|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured.<br /><br />Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes.(Citation: Adventures of a Keystroke) Some methods include:<br /><br />* Hooking API callbacks used for processing keystrokes. Unlike [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004), this focuses solely on API functions intended for processing keystroke data.<br /><br />* Reading raw keystroke data from the hardware buffer.<br /><br />* Windows Registry modifications.<br /><br />* Custom drivers.<br /><br />* [Modify System Image](https://attack.mitre.org/techniques/T1601) may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions.(Citation: Cisco Blog Legacy Device Attacks) <br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/568.html",
        "description": "none",
        "external_id": "CAPEC-568"
      },
      {
        "source_name": "Adventures of a Keystroke",
        "url": "http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf",
        "description": "Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.",
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
    "id": "attack-pattern--a2029942-0a85-4947-b23c-ca434698171d",
    "platform": "macos|windows",
    "tid": "T1056.002",
    "technique": "GUI Input Capture",
    "tactic": "collection",
    "datasources": "powershell-logs|process-command-line-parameters|process-monitoring|user-interface",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002)).<br /><br />Adversaries may mimic this functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite.(Citation: OSX Malware Exploits MacKeeper) This type of prompt can be used to collect credentials via various languages such as AppleScript(Citation: LogRhythm Do You Trust Oct 2014)(Citation: OSX Keydnap malware) and PowerShell(Citation: LogRhythm Do You Trust Oct 2014)(Citation: Enigma Phishing for Credentials Jan 2015). <br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/659.html",
        "description": "none",
        "external_id": "CAPEC-659"
      },
      {
        "source_name": "OSX Malware Exploits MacKeeper",
        "url": "https://baesystemsai.blogspot.com/2015/06/new-mac-os-malware-exploits-mackeeper.html",
        "description": "Sergei Shevchenko. (2015, June 4). New Mac OS Malware Exploits Mackeeper. Retrieved July 3, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "LogRhythm Do You Trust Oct 2014",
        "url": "https://logrhythm.com/blog/do-you-trust-your-computer/",
        "description": "Foss, G. (2014, October 3). Do You Trust Your Computer?. Retrieved December 17, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "OSX Keydnap malware",
        "url": "https://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-hungry-credentials/",
        "description": "Marc-Etienne M.Leveille. (2016, July 6). New OSX/Keydnap malware is hungry for credentials. Retrieved July 3, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Enigma Phishing for Credentials Jan 2015",
        "url": "https://enigma0x3.net/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/",
        "description": "Nelson, M. (2015, January 21). Phishing for Credentials: If you want it, just ask!. Retrieved December 17, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--69e5226d-05dc-4f15-95d7-44f5ed78d06e",
    "platform": "linux|macos|windows",
    "tid": "T1056.003",
    "technique": "Web Portal Capture",
    "tactic": "collection",
    "datasources": "file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service.<br /><br />This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through [External Remote Services](https://attack.mitre.org/techniques/T1133) and [Valid Accounts](https://attack.mitre.org/techniques/T1078) or as part of the initial compromise by exploitation of the externally facing web service.(Citation: Volexity Virtual Private Keylogging)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/569.html",
        "description": "none",
        "external_id": "CAPEC-569"
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
    "id": "attack-pattern--f5946b5e-9408-485f-a7f7-b5efc88909b6",
    "platform": "windows",
    "tid": "T1056.004",
    "technique": "Credential API Hooking",
    "tactic": "collection",
    "datasources": "api-monitoring|binary-file-metadata|dll-monitoring|loaded-dlls|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may hook into Windows application programming interface (API) functions to collect user credentials. Malicious hooking mechanisms may capture API calls that include parameters that reveal user authentication credentials.(Citation: Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017) Unlike [Keylogging](https://attack.mitre.org/techniques/T1056/001),  this technique focuses specifically on API functions that include parameters that reveal user credentials. Hooking involves redirecting calls to these functions and can be implemented via:<br /><br />* **Hooks procedures**, which intercept and execute designated code in response to events such as messages, keystrokes, and mouse inputs.(Citation: Microsoft Hook Overview)(Citation: Endgame Process Injection July 2017)<br /><br />* **Import address table (IAT) hooking**, which use modifications to a process’s IAT, where pointers to imported API functions are stored.(Citation: Endgame Process Injection July 2017)(Citation: Adlice Software IAT Hooks Oct 2014)(Citation: MWRInfoSecurity Dynamic Hooking 2015)<br /><br />* **Inline hooking**, which overwrites the first bytes in an API function to redirect code flow.(Citation: Endgame Process Injection July 2017)(Citation: HighTech Bridge Inline Hooking Sept 2011)(Citation: MWRInfoSecurity Dynamic Hooking 2015)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017",
        "url": "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=TrojanSpy:Win32/Ursnif.gen!I&threatId=-2147336918",
        "description": "Microsoft. (2017, September 15). TrojanSpy:Win32/Ursnif.gen!I. Retrieved December 18, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Hook Overview",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms644959.aspx",
        "description": "Microsoft. (n.d.). Hooks Overview. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Adlice Software IAT Hooks Oct 2014",
        "url": "https://www.adlice.com/userland-rootkits-part-1-iat-hooks/",
        "description": "Tigzy. (2014, October 15). Userland Rootkits: Part 1, IAT hooks. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "MWRInfoSecurity Dynamic Hooking 2015",
        "url": "https://www.mwrinfosecurity.com/our-thinking/dynamic-hooking-techniques-user-mode/",
        "description": "Hillman, M. (2015, August 8). Dynamic Hooking Techniques: User Mode. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "HighTech Bridge Inline Hooking Sept 2011",
        "url": "https://www.exploit-db.com/docs/17802.pdf",
        "description": "Mariani, B. (2011, September 6). Inline Hooking in Windows. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Volatility Detecting Hooks Sept 2012",
        "url": "https://volatility-labs.blogspot.com/2012/09/movp-31-detecting-malware-hooks-in.html",
        "description": "Volatility Labs. (2012, September 24). MoVP 3.1 Detecting Malware Hooks in the Windows GUI Subsystem. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "PreKageo Winhook Jul 2011",
        "url": "https://github.com/prekageo/winhook",
        "description": "Prekas, G. (2011, July 11). Winhook. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Jay GetHooks Sept 2011",
        "url": "https://github.com/jay/gethooks",
        "description": "Satiro, J. (2011, September 14). GetHooks. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Zairon Hooking Dec 2006",
        "url": "https://zairon.wordpress.com/2006/12/06/any-application-defined-hook-procedure-on-my-machine/",
        "description": "Felici, M. (2006, December 6). Any application-defined hook procedure on my machine?. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "EyeofRa Detecting Hooking June 2017",
        "url": "https://eyeofrablog.wordpress.com/2017/06/27/windows-keylogger-part-2-defense-against-user-land/",
        "description": "Eye of Ra. (2017, June 27). Windows Keylogger Part 2: Defense against user-land. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GMER Rootkits",
        "url": "http://www.gmer.net/",
        "description": "GMER. (n.d.). GMER. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Process Snapshot",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms686701.aspx",
        "description": "Microsoft. (n.d.). Taking a Snapshot and Viewing Processes. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "StackExchange Hooks Jul 2012",
        "url": "https://security.stackexchange.com/questions/17904/what-are-the-methods-to-find-hooked-functions-and-apis",
        "description": "Stack Exchange - Security. (2012, July 31). What are the methods to find hooked functions and APIs?. Retrieved December 12, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1c34f7aa-9341-4a48-bfab-af22e51aca6c",
    "platform": "linux|macos|windows",
    "tid": "T1074.001",
    "technique": "Local Data Staging",
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
    "technique_description": "Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--359b00ad-9425-420b-bba5-6de8d600cbc0",
    "platform": "linux|macos|windows|aws|gcp|azure",
    "tid": "T1074.002",
    "technique": "Remote Data Staging",
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
    "technique_description": "Adversaries may stage data collected from multiple systems in a central location or directory on one system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.<br /><br />In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may [Create Cloud Instance](https://attack.mitre.org/techniques/T1578/002) and stage data in that instance.(Citation: Mandiant M-Trends 2020)<br /><br />By staging data on one system prior to Exfiltration, adversaries can minimize the number of connections made to their C2 server and better evade detection.<br /><br />",
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
    "id": "attack-pattern--1e9eb839-294b-48cc-b0d3-c45555a2a004",
    "platform": "windows",
    "tid": "T1114.001",
    "technique": "Local Email Collection",
    "tactic": "collection",
    "datasources": "authentication-logs|file-monitoring|mail-server|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files.<br /><br />Outlook stores data locally in offline data files with an extension of .ost. Outlook 2010 and later supports .ost file sizes up to 50GB, while earlier versions of Outlook support up to 20GB.(Citation: Outlook File Sizes) IMAP accounts in Outlook 2013 (and earlier) and POP accounts use Outlook Data Files (.pst) as opposed to .ost, whereas IMAP accounts in Outlook 2016 (and later) use .ost files. Both types of Outlook data files are typically stored in `C:\\Users\\<username>\\Documents\\Outlook Files` or `C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Outlook`.(Citation: Microsoft Outlook Files)<br /><br />",
    "technique_references": [
      {
        "source_name": "Outlook File Sizes",
        "url": "https://practical365.com/clients/office-365-proplus/outlook-cached-mode-ost-file-sizes/",
        "description": "N. O'Bryan. (2018, May 30). Managing Outlook Cached Mode and OST File Sizes. Retrieved February 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Outlook Files",
        "url": "https://support.office.com/en-us/article/introduction-to-outlook-data-files-pst-and-ost-222eaf92-a995-45d9-bde2-f331f60e2790",
        "description": "Microsoft. (n.d.). Introduction to Outlook Data Files (.pst and .ost). Retrieved February 19, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b4694861-542c-48ea-9eb1-10d356e7140a",
    "platform": "office-365|windows",
    "tid": "T1114.002",
    "technique": "Remote Email Collection",
    "tactic": "collection",
    "datasources": "authentication-logs|email-gateway|mail-server|office-365-trace-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may target an Exchange server or Office 365 to collect sensitive information. Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services or Office 365 to access email using credentials or access tokens. Tools such as [MailSniper](https://attack.mitre.org/software/S0413) can be used to automate searches for specific keywords.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--7d77a07d-02fe-4e88-8bd9-e9c008c01bf0",
    "platform": "office-365|windows",
    "tid": "T1114.003",
    "technique": "Email Forwarding Rule",
    "tactic": "collection",
    "datasources": "email-gateway|mail-server|office-365-trace-logs|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may setup email forwarding rules to collect sensitive information. Adversaries may abuse email-forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations.(Citation: US-CERT TA18-068A 2018) Outlook and Outlook Web App (OWA) allow users to create inbox rules for various email functions, including forwarding to a different recipient. Messages can be forwarded to internal or external recipients, and there are no restrictions limiting the extent of this rule. Administrators may also create forwarding rules for user accounts with the same considerations and outcomes.(Citation: Microsoft Tim McMichael Exchange Mail Forwarding 2) <br /><br />Any user or administrator within the organization (or adversary with valid credentials) can create rules to automatically forward all received messages to another recipient, forward emails to different locations based on the sender, and more.<br /><br />",
    "technique_references": [
      {
        "source_name": "US-CERT TA18-068A 2018",
        "url": "https://www.us-cert.gov/ncas/alerts/TA18-086A",
        "description": "US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Tim McMichael Exchange Mail Forwarding 2",
        "url": "https://blogs.technet.microsoft.com/timmcmic/2015/06/08/exchange-and-office-365-mail-forwarding-2/",
        "description": "McMichael, T.. (2015, June 8). Exchange and Office 365 Mail Forwarding. Retrieved October 8, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7ad38ef1-381a-406d-872a-38b136eb5ecc",
    "platform": "saas",
    "tid": "T1213.001",
    "technique": "Confluence",
    "tactic": "collection",
    "datasources": "authentication-logs|third-party-application-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may leverage Confluence repositories to mine valuable information. Often found in development environments alongside Atlassian JIRA, Confluence is generally used to store development-related documentation, however, in general may contain more diverse categories of useful information, such as:<br /><br />* Policies, procedures, and standards<br /><br />* Physical / logical network diagrams<br /><br />* System architecture diagrams<br /><br />* Technical system documentation<br /><br />* Testing / development credentials<br /><br />* Work / project schedules<br /><br />* Source code snippets<br /><br />* Links to network shares and other internal resources<br /><br />",
    "technique_references": [
      {
        "source_name": "Atlassian Confluence Logging",
        "url": "https://confluence.atlassian.com/confkb/how-to-enable-user-access-logging-182943.html",
        "description": "Atlassian. (2018, January 9). How to Enable User Access Logging. Retrieved April 4, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0c4b4fda-9062-47da-98b9-ceae2dcf052a",
    "platform": "windows|office-365",
    "tid": "T1213.002",
    "technique": "Sharepoint",
    "tactic": "collection",
    "datasources": "application-logs|authentication-logs|office-365-audit-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may leverage the SharePoint repository as a source to mine valuable information. SharePoint will often contain useful information for an adversary to learn about the structure and functionality of the internal network and systems. For example, the following is a list of example information that may hold potential value to an adversary and may also be found on SharePoint:<br /><br />* Policies, procedures, and standards<br /><br />* Physical / logical network diagrams<br /><br />* System architecture diagrams<br /><br />* Technical system documentation<br /><br />* Testing / development credentials<br /><br />* Work / project schedules<br /><br />* Source code snippets<br /><br />* Links to network shares and other internal resources<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft SharePoint Logging",
        "url": "https://support.office.com/en-us/article/configure-audit-settings-for-a-site-collection-a9920c97-38c0-44f2-8bcb-4cf1e2ae22d2",
        "description": "Microsoft. (2017, July 19). Configure audit settings for a site collection. Retrieved April 4, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--650c784b-7504-4df7-ab2c-4ea882384d1e",
    "platform": "windows",
    "tid": "T1557.001",
    "technique": "LLMNR/NBT-NS Poisoning and SMB Relay",
    "tactic": "collection",
    "datasources": "netflow-enclave-netflow|packet-capture|windows-event-logs|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials. <br /><br />Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. NBT-NS identifies systems on a local network by their NetBIOS name. (Citation: Wikipedia LLMNR) (Citation: TechNet NetBIOS)<br /><br />Adversaries can spoof an authoritative source for name resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they know the identity of the requested host, effectively poisoning the service so that the victims will communicate with the adversary controlled system. If the requested host belongs to a resource that requires identification/authentication, the username and NTLMv2 hash will then be sent to the adversary controlled system. The adversary can then collect the hash information sent over the wire through tools that monitor the ports for traffic or through [Network Sniffing](https://attack.mitre.org/techniques/T1040) and crack the hashes offline through [Brute Force](https://attack.mitre.org/techniques/T1110) to obtain the plaintext passwords. In some cases where an adversary has access to a system that is in the authentication path between systems or when automated scans that use credentials attempt to authenticate to an adversary controlled system, the NTLMv2 hashes can be intercepted and relayed to access and execute code against a target system. The relay step can happen in conjunction with poisoning but may also be independent of it. (Citation: byt3bl33d3r NTLM Relaying)(Citation: Secure Ideas SMB Relay)<br /><br />Several tools exist that can be used to poison name services within local networks such as NBNSpoof, Metasploit, and [Responder](https://attack.mitre.org/software/S0174). (Citation: GitHub NBNSpoof) (Citation: Rapid7 LLMNR Spoofer) (Citation: GitHub Responder)<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia LLMNR",
        "url": "https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution",
        "description": "Wikipedia. (2016, July 7). Link-Local Multicast Name Resolution. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet NetBIOS",
        "url": "https://technet.microsoft.com/library/cc958811.aspx",
        "description": "Microsoft. (n.d.). NetBIOS Name Resolution. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "byt3bl33d3r NTLM Relaying",
        "url": "https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html",
        "description": "Salvati, M. (2017, June 2). Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes). Retrieved February 7, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Secure Ideas SMB Relay",
        "url": "https://blog.secureideas.com/2018/04/ever-run-a-relay-why-smb-relays-should-be-on-your-mind.html",
        "description": "Kuehn, E. (2018, April 11). Ever Run a Relay? Why SMB Relays Should Be On Your Mind. Retrieved February 7, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub NBNSpoof",
        "url": "https://github.com/nomex/nbnspoof",
        "description": "Nomex. (2014, February 7). NBNSpoof. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Rapid7 LLMNR Spoofer",
        "url": "https://www.rapid7.com/db/modules/auxiliary/spoof/llmnr/llmnr_response",
        "description": "Francois, R. (n.d.). LLMNR Spoofer. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Responder",
        "url": "https://github.com/SpiderLabs/Responder",
        "description": "Gaffie, L. (2016, August 25). Responder. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Sternsecurity LLMNR-NBTNS",
        "url": "https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning",
        "description": "Sternstein, J. (2013, November). Local Network Attacks: LLMNR and NBT-NS Poisoning. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Conveigh",
        "url": "https://github.com/Kevin-Robertson/Conveigh",
        "description": "Robertson, K. (2016, August 28). Conveigh. Retrieved November 17, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cabe189c-a0e3-4965-a473-dcff00f17213",
    "platform": "linux|windows|macos",
    "tid": "T1557.002",
    "technique": "ARP Cache Poisoning",
    "tactic": "collection",
    "datasources": "netflow-enclave-netflow|packet-capture",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002).<br /><br />The ARP protocol is used to resolve IPv4 addresses to link layer addresses, such as a media access control (MAC) address.(Citation: RFC826 ARP) Devices in a local network segment communicate with each other by using link layer addresses. If a networked device does not have the link layer address of a particular networked device, it may send out a broadcast ARP request to the local network to translate the IP address to a MAC address. The device with the associated IP address directly replies with its MAC address. The networked device that made the ARP request will then use as well as store that information in its ARP cache.<br /><br />An adversary may passively wait for an ARP request to poison the ARP cache of the requesting device. The adversary may reply with their MAC address, thus deceiving the victim by making them believe that they are communicating with the intended networked device. For the adversary to poison the ARP cache, their reply must be faster than the one made by the legitimate IP address owner. Adversaries may also send a gratuitous ARP reply that maliciously announces the ownership of a particular IP address to all the devices in the local network segment.<br /><br />The ARP protocol is stateless and does not require authentication. Therefore, devices may wrongly add or update the MAC address of the IP address in their ARP cache.(Citation: Sans ARP Spoofing Aug 2003)(Citation: Cylance Cleaver)<br /><br />Adversaries may use ARP cache poisoning as a means to man-in-the-middle (MiTM) network traffic. This activity may be used to collect and/or relay data such as credentials, especially those sent over an insecure, unencrypted protocol.(Citation: Sans ARP Spoofing Aug 2003)<br /><br />",
    "technique_references": [
      {
        "source_name": "RFC826 ARP",
        "url": "https://tools.ietf.org/html/rfc826",
        "description": "Plummer, D. (1982, November). An Ethernet Address Resolution Protocol. Retrieved October 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Sans ARP Spoofing Aug 2003",
        "url": "https://pen-testing.sans.org/resources/papers/gcih/real-world-arp-spoofing-105411",
        "description": "Siles, R. (2003, August). Real World ARP Spoofing. Retrieved October 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cylance Cleaver",
        "url": "https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf",
        "description": "Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--00f90846-cbd1-4fc5-9233-df5c2bf2a662",
    "platform": "linux|macos|windows",
    "tid": "T1560.001",
    "technique": "Archive via Utility",
    "tactic": "collection",
    "datasources": "binary-file-metadata|file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities. Many utilities exist that can archive data, including 7-Zip(Citation: 7zip Homepage), WinRAR(Citation: WinRAR Homepage), and WinZip(Citation: WinZip Homepage). Most utilities include functionality to encrypt and/or compress data.<br /><br />Some 3rd party utilities may be preinstalled, such as `tar` on Linux and macOS or `zip` on Windows systems.<br /><br />",
    "technique_references": [
      {
        "source_name": "7zip Homepage",
        "url": "https://www.7-zip.org/",
        "description": "I. Pavlov. (2019). 7-Zip. Retrieved February 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "WinRAR Homepage",
        "url": "https://www.rarlab.com/",
        "description": "A. Roshal. (2020). RARLAB. Retrieved February 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "WinZip Homepage",
        "url": "https://www.winzip.com/win/en/",
        "description": "Corel Corporation. (2020). WinZip. Retrieved February 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Wikipedia File Header Signatures",
        "url": "https://en.wikipedia.org/wiki/List_of_file_signatures",
        "description": "Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--41868330-6ee2-4d0f-b743-9f2294c3c9b6",
    "platform": "linux|macos|windows",
    "tid": "T1560.002",
    "technique": "Archive via Library",
    "tactic": "collection",
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
    "technique_description": "An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries. Many libraries exist that can archive data, including [Python](https://attack.mitre.org/techniques/T1059/006) rarfile (Citation: PyPI RAR), libzip (Citation: libzip), and zlib (Citation: Zlib Github). Most libraries include functionality to encrypt and/or compress data.<br /><br />Some archival libraries are preinstalled on systems, such as bzip2 on macOS and Linux, and zip on Windows. Note that the libraries are different from the utilities. The libraries can be linked against when compiling, while the utilities require spawning a subshell, or a similar execution mechanism.<br /><br />",
    "technique_references": [
      {
        "source_name": "PyPI RAR",
        "url": "https://pypi.org/project/rarfile/",
        "description": "mkz. (2020). rarfile 3.1. Retrieved February 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "libzip",
        "url": "https://libzip.org/",
        "description": "D. Baron, T. Klausner. (2020). libzip. Retrieved February 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Zlib Github",
        "url": "https://github.com/madler/zlib",
        "description": "madler. (2017). zlib. Retrieved February 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Wikipedia File Header Signatures",
        "url": "https://en.wikipedia.org/wiki/List_of_file_signatures",
        "description": "Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--143c0cbb-a297-4142-9624-87ffc778980b",
    "platform": "linux|macos|windows",
    "tid": "T1560.003",
    "technique": "Archive via Custom Method",
    "tactic": "collection",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or utility references. Custom implementations of well-known compression algorithms have also been used.(Citation: ESET Sednit Part 2)<br /><br />",
    "technique_references": [
      {
        "source_name": "ESET Sednit Part 2",
        "url": "http://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part-2.pdf",
        "description": "ESET. (2016, October). En Route with Sednit - Part 2: Observing the Comings and Goings. Retrieved November 21, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ee7ff928-801c-4f34-8a99-3df965e581a5",
    "platform": "network",
    "tid": "T1602.001",
    "technique": "SNMP (MIB Dump)",
    "tactic": "collection",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information in a network managed using Simple Network Management Protocol (SNMP).<br /><br />The MIB is a configuration repository that stores variable information accessible via SNMP in the form of object identifiers (OID). Each OID identifies a variable that can be read or set and permits active management tasks, such as configuration changes, through remote modification of these variables. SNMP can give administrators great insight in their systems, such as, system information, description of hardware, physical location, and software packages(Citation: SANS Information Security Reading Room Securing SNMP Securing SNMP). The MIB may also contain device operational information, including running configuration, routing table, and interface details.<br /><br />Adversaries may use SNMP queries to collect MIB content directly from SNMP-managed devices in order to collect network information that allows the adversary to build network maps and facilitate future targeted exploitation.(Citation: US-CERT-TA18-106A)(Citation: Cisco Blog Legacy Device Attacks) <br /><br />",
    "technique_references": [
      {
        "source_name": "SANS Information Security Reading Room Securing SNMP Securing SNMP",
        "url": "https://www.sans.org/reading-room/whitepapers/networkdevs/securing-snmp-net-snmp-snmpv3-1051",
        "description": "Michael Stump. (2003). Information Security Reading Room Securing SNMP: A Look atNet-SNMP (SNMPv3). Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "US-CERT-TA18-106A",
        "url": "https://www.us-cert.gov/ncas/alerts/TA18-106A",
        "description": "US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Blog Legacy Device Attacks",
        "url": "https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954",
        "description": "Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.",
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
    "id": "attack-pattern--52759bf1-fe12-4052-ace6-c5b0cf7dd7fd",
    "platform": "network",
    "tid": "T1602.002",
    "technique": "Network Device Configuration Dump",
    "tactic": "collection",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may access network configuration files to collect sensitive data about the device and the network. The network configuration is a file containing parameters that determine the operation of the device. The device typically stores an in-memory copy of the configuration while operating, and a separate configuration on non-volatile storage to load after device reset. Adversaries can inspect the configuration files to reveal information about the target network and its layout, the network device and its software, or identifying legitimate accounts and credentials for later use.<br /><br />Adversaries can use common management tools and protocols, such as Simple Network Management Protocol (SNMP) and Smart Install (SMI), to access network configuration files. (Citation: US-CERT TA18-106A Network Infrastructure Devices 2018) (Citation: Cisco Blog Legacy Device Attacks) These tools may be used to query specific data from a configuration repository or configure the device to export the configuration for later analysis. <br /><br />",
    "technique_references": [
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
        "source_name": "US-CERT TA18-068A 2018",
        "url": "https://www.us-cert.gov/ncas/alerts/TA18-086A",
        "description": "US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.",
        "external_id": "none"
      }
    ]
  }
]
