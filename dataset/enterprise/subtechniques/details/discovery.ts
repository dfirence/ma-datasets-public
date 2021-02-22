export const DISCOVERY_SUBTECHNIQUE_DETAILS = [
  {
    "id": "attack-pattern--a01bf75f-00b2-4568-a58f-565ff9bf202b",
    "platform": "linux|macos|windows",
    "tid": "T1069.001",
    "technique": "Local Groups",
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
    "technique_description": "Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.<br /><br />Commands such as <code>net localgroup</code> of the [Net](https://attack.mitre.org/software/S0039) utility, <code>dscl . -list /Groups</code> on macOS, and <code>groups</code> on Linux can list local groups.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--2aed01ad-3df3-4410-a8cb-11ea4ded587c",
    "platform": "linux|macos|windows",
    "tid": "T1069.002",
    "technique": "Domain Groups",
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
    "technique_description": "Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.<br /><br />Commands such as <code>net group /domain</code> of the [Net](https://attack.mitre.org/software/S0039) utility,  <code>dscacheutil -q group</code> on macOS, and <code>ldapsearch</code> on Linux can list domain-level groups.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--16e94db9-b5b1-4cd0-b851-f38fbd0a70f2",
    "platform": "office-365|azure-ad|gcp|saas|azure|aws",
    "tid": "T1069.003",
    "technique": "Cloud Groups",
    "tactic": "discovery",
    "datasources": "api-monitoring|aws-cloudtrail-logs|azure-activity-logs|gcp-audit-logs|office-365-account-logs|process-command-line-parameters|process-monitoring|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to find cloud groups and permission settings. The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated with a particular group.<br /><br />With authenticated access there are several tools that can be used to find permissions groups. The <code>Get-MsolRole</code> PowerShell cmdlet can be used to obtain roles and permissions groups for Exchange and Office 365 accounts.(Citation: Microsoft Msolrole)(Citation: GitHub Raindance)<br /><br />Azure CLI (AZ CLI) also provides an interface to obtain permissions groups with authenticated access to a domain. The command <code>az ad user get-member-groups</code> will list groups associated to a user account.(Citation: Microsoft AZ CLI)(Citation: Black Hills Red Teaming MS AD Azure, 2018)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Msolrole",
        "url": "https://docs.microsoft.com/en-us/powershell/module/msonline/get-msolrole?view=azureadps-1.0",
        "description": "Microsoft. (n.d.). Get-MsolRole. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Raindance",
        "url": "https://github.com/True-Demon/raindance",
        "description": "Stringer, M.. (2018, November 21). RainDance. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft AZ CLI",
        "url": "https://docs.microsoft.com/en-us/cli/azure/ad/user?view=azure-cli-latest",
        "description": "Microsoft. (n.d.). az ad user. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Black Hills Red Teaming MS AD Azure, 2018",
        "url": "https://www.blackhillsinfosec.com/red-teaming-microsoft-part-1-active-directory-leaks-via-azure/",
        "description": "Felch, M.. (2018, August 31). Red Teaming Microsoft Part 1 Active Directory Leaks via Azure. Retrieved October 6, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--25659dd6-ea12-45c4-97e6-381e3e4b593e",
    "platform": "linux|macos|windows",
    "tid": "T1087.001",
    "technique": "Local Account",
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
    "technique_description": "Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.<br /><br />Commands such as <code>net user</code> and <code>net localgroup</code> of the [Net](https://attack.mitre.org/software/S0039) utility and <code>id</code> and <code>groups</code>on macOS and Linux can list local users and groups. On Linux, local users can also be enumerated through the use of the <code>/etc/passwd</code> file.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--21875073-b0ee-49e3-9077-1e2a885359af",
    "platform": "linux|macos|windows",
    "tid": "T1087.002",
    "technique": "Domain Account",
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
    "technique_description": "Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior.<br /><br />Commands such as <code>net user /domain</code> and <code>net group /domain</code> of the [Net](https://attack.mitre.org/software/S0039) utility, <code>dscacheutil -q group</code>on macOS, and <code>ldapsearch</code> on Linux can list domain users and groups.<br /><br />",
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
    "id": "attack-pattern--4bc31b94-045b-4752-8920-aebaebdb6470",
    "platform": "windows|office-365",
    "tid": "T1087.003",
    "technique": "Email Account",
    "tactic": "discovery",
    "datasources": "office-365-account-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to get a listing of email addresses and accounts. Adversaries may try to dump Exchange address lists such as global address lists (GALs).(Citation: Microsoft Exchange Address Lists)<br /><br />In on-premises Exchange and Exchange Online, the<code>Get-GlobalAddressList</code> PowerShell cmdlet can be used to obtain email addresses and accounts from a domain using an authenticated session.(Citation: Microsoft getglobaladdresslist)(Citation: Black Hills Attacking Exchange MailSniper, 2016)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Exchange Address Lists",
        "url": "https://docs.microsoft.com/en-us/exchange/email-addresses-and-address-books/address-lists/address-lists?view=exchserver-2019",
        "description": "Microsoft. (2020, February 7). Address lists in Exchange Server. Retrieved March 26, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft getglobaladdresslist",
        "url": "https://docs.microsoft.com/en-us/powershell/module/exchange/email-addresses-and-address-books/get-globaladdresslist",
        "description": "Microsoft. (n.d.). Get-GlobalAddressList. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Black Hills Attacking Exchange MailSniper, 2016",
        "url": "https://www.blackhillsinfosec.com/attacking-exchange-with-mailsniper/",
        "description": "Bullock, B.. (2016, October 3). Attacking Exchange with MailSniper. Retrieved October 6, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--8f104855-e5b7-4077-b1f5-bc3103b41abe",
    "platform": "aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1087.004",
    "technique": "Cloud Account",
    "tactic": "discovery",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|office-365-account-logs|process-command-line-parameters|process-monitoring|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to get a listing of cloud accounts. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application.<br /><br />With authenticated access there are several tools that can be used to find accounts. The <code>Get-MsolRoleMember</code> PowerShell cmdlet can be used to obtain account names given a role or permissions group in Office 365.(Citation: Microsoft msolrolemember)(Citation: GitHub Raindance) The Azure CLI (AZ CLI) also provides an interface to obtain user accounts with authenticated access to a domain. The command <code>az ad user list</code> will list all users within a domain.(Citation: Microsoft AZ CLI)(Citation: Black Hills Red Teaming MS AD Azure, 2018) <br /><br />The AWS command <code>aws iam list-users</code> may be used to obtain a list of users in the current account while <code>aws iam list-roles</code> can obtain IAM roles that have a specified path prefix.(Citation: AWS List Roles)(Citation: AWS List Users) In GCP, <code>gcloud iam service-accounts list</code> and <code>gcloud projects get-iam-policy</code> may be used to obtain a listing of service accounts and users in a project.(Citation: Google Cloud - IAM Servie Accounts List API)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft msolrolemember",
        "url": "https://docs.microsoft.com/en-us/powershell/module/msonline/get-msolrolemember?view=azureadps-1.0",
        "description": "Microsoft. (n.d.). Get-MsolRoleMember. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Raindance",
        "url": "https://github.com/True-Demon/raindance",
        "description": "Stringer, M.. (2018, November 21). RainDance. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft AZ CLI",
        "url": "https://docs.microsoft.com/en-us/cli/azure/ad/user?view=azure-cli-latest",
        "description": "Microsoft. (n.d.). az ad user. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Black Hills Red Teaming MS AD Azure, 2018",
        "url": "https://www.blackhillsinfosec.com/red-teaming-microsoft-part-1-active-directory-leaks-via-azure/",
        "description": "Felch, M.. (2018, August 31). Red Teaming Microsoft Part 1 Active Directory Leaks via Azure. Retrieved October 6, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "AWS List Roles",
        "url": "https://docs.aws.amazon.com/cli/latest/reference/iam/list-roles.html",
        "description": "Amazon. (n.d.). List Roles. Retrieved August 11, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "AWS List Users",
        "url": "https://docs.aws.amazon.com/cli/latest/reference/iam/list-users.html",
        "description": "Amazon. (n.d.). List Users. Retrieved August 11, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Google Cloud - IAM Servie Accounts List API",
        "url": "https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/list",
        "description": "Google. (2020, June 23). gcloud iam service-accounts list. Retrieved August 4, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--29be378d-262d-4e99-b00d-852d573628e6",
    "platform": "linux|macos|windows",
    "tid": "T1497.001",
    "technique": "System Checks",
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
    "technique_description": "Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors. <br /><br />Specific checks may will vary based on the target and/or adversary, but may involve behaviors such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047), [PowerShell](https://attack.mitre.org/techniques/T1059/001), [System Information Discovery](https://attack.mitre.org/techniques/T1082), and [Query Registry](https://attack.mitre.org/techniques/T1012) to obtain system information and search for VME artifacts. Adversaries may search for VME artifacts in memory, processes, file system, hardware, and/or the Registry. Adversaries may use scripting to automate these checks  into one script and then have the program exit if it determines the system to be a virtual environment. <br /><br />Checks could include generic system properties such as uptime and samples of network traffic. Adversaries may also check the network adapters addresses, CPU core count, and available memory/drive size. <br /><br />Other common checks may enumerate services running that are unique to these applications, installed programs on the system, manufacturer/product fields for strings relating to virtual machine applications, and VME-specific hardware/processor instructions.(Citation: McAfee Virtual Jan 2017) In applications like VMWare, adversaries can also use a special I/O port to send commands and receive output. <br /><br /> <br /><br />Hardware checks, such as the presence of the fan, temperature, and audio devices, could also be used to gather evidence that can be indicative a virtual environment. Adversaries may also query for specific readings from these devices.(Citation: Unit 42 OilRig Sept 2018)<br /><br />",
    "technique_references": [
      {
        "source_name": "McAfee Virtual Jan 2017",
        "url": "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/stopping-malware-fake-virtual-machine/",
        "description": "Roccia, T. (2017, January 19). Stopping Malware With a Fake Virtual Machine. Retrieved April 17, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Unit 42 OilRig Sept 2018",
        "url": "https://researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/",
        "description": "Falcone, R., et al. (2018, September 04). OilRig Targets a Middle Eastern Government and Adds Evasion Techniques to OopsIE. Retrieved September 24, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--91541e7e-b969-40c6-bbd8-1b5352ec2938",
    "platform": "linux|macos|windows",
    "tid": "T1497.002",
    "technique": "User Activity Based Checks",
    "tactic": "discovery",
    "datasources": "process-command-line-parameters|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors. <br /><br />Adversaries may search for user activity on the host based on variables such as the speed/frequency of mouse movements and clicks (Citation: Sans Virtual Jan 2016) , browser history, cache, bookmarks, or number of files in common directories such as home or the desktop. Other methods may rely on specific user interaction with the system before the malicious code is activated, such as waiting for a document to close before activating a macro (Citation: Unit 42 Sofacy Nov 2018) or waiting for a user to double click on an embedded image to activate.(Citation: FireEye FIN7 April 2017) <br /><br />",
    "technique_references": [
      {
        "source_name": "Sans Virtual Jan 2016",
        "url": "https://www.sans.org/reading-room/whitepapers/forensics/detecting-malware-sandbox-evasion-techniques-36667",
        "description": "Keragala, D. (2016, January 16). Detecting Malware and Sandbox Evasion Techniques. Retrieved April 17, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Unit 42 Sofacy Nov 2018",
        "url": "https://unit42.paloaltonetworks.com/unit42-sofacy-continues-global-attacks-wheels-new-cannon-trojan/",
        "description": "Falcone, R., Lee, B.. (2018, November 20). Sofacy Continues Global Attacks and Wheels Out New ‘Cannon’ Trojan. Retrieved April 23, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye FIN7 April 2017",
        "url": "https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html",
        "description": "Carr, N., et al. (2017, April 24). FIN7 Evolution and the Phishing LNK. Retrieved April 24, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--4bed873f-0b7d-41d4-b93a-b6905d1f90b0",
    "platform": "linux|macos|windows",
    "tid": "T1497.003",
    "technique": "Time Based Evasion",
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
    "technique_description": "Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include timers or other triggers to avoid a virtual machine environment (VME) or sandbox, specifically those that are automated or only operate for a limited amount of time.<br /><br />Adversaries may employ various time-based evasions, such as delaying malware functionality upon initial execution using programmatic sleep commands or native system scheduling functionality (ex: [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)). Delays may also be based on waiting for specific victim conditions to be met (ex: system time, events, etc.) or employ scheduled [Multi-Stage Channels](https://attack.mitre.org/techniques/T1104) to avoid analysis and scrutiny. <br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--cba37adb-d6fb-4610-b069-dd04c0643384",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1518.001",
    "technique": "Security Software Discovery",
    "tactic": "discovery",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|file-monitoring|process-command-line-parameters|process-monitoring|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as firewall rules and anti-virus. Adversaries may use the information from [Security Software Discovery](https://attack.mitre.org/techniques/T1518/001) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br /><br />Example commands that can be used to obtain security software information are [netsh](https://attack.mitre.org/software/S0108), <code>reg query</code> with [Reg](https://attack.mitre.org/software/S0075), <code>dir</code> with [cmd](https://attack.mitre.org/software/S0106), and [Tasklist](https://attack.mitre.org/software/S0057), but other indicators of discovery behavior may be more specific to the type of software or security system the adversary is looking for. It is becoming more common to see macOS malware perform checks for LittleSnitch and KnockKnock software.<br /><br />Adversaries may also utilize cloud APIs to discover the configurations of firewall rules within an environment.(Citation: Expel IO Evil in AWS)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/581.html",
        "description": "none",
        "external_id": "CAPEC-581"
      },
      {
        "source_name": "Expel IO Evil in AWS",
        "url": "https://expel.io/blog/finding-evil-in-aws/",
        "description": "A. Randazzo, B. Manahan and S. Lipton. (2020, April 28). Finding Evil in AWS. Retrieved June 25, 2020.",
        "external_id": "none"
      }
    ]
  }
]
