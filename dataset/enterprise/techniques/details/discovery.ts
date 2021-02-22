 [
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
    "technique_description": "Adversaries may try to get information about registered services. Commands that may obtain information about services using operating system utilities are \"sc,\" \"tasklist /svc\" using [Tasklist](https://attack.mitre.org/software/S0057), and \"net start\" using [Net](https://attack.mitre.org/software/S0039), but adversaries may also use other tools as well. Adversaries may use the information from [System Service Discovery](https://attack.mitre.org/techniques/T1007) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br /><br />",
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
    "technique_description": "Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger.<br /><br />",
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
    "technique_description": "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.<br /><br />The Registry contains a significant amount of information about the operating system, configuration, software, and security.(Citation: Wikipedia Windows Registry) Information can easily be queried using the [Reg](https://attack.mitre.org/software/S0075) utility, though other means to access the Registry exist. Some of the information may help adversaries to further their operation within a network. Adversaries may use the information from [Query Registry](https://attack.mitre.org/techniques/T1012) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br /><br />",
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
    "technique_description": "Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include [Arp](https://attack.mitre.org/software/S0099), [ipconfig](https://attack.mitre.org/software/S0100)/[ifconfig](https://attack.mitre.org/software/S0101), [nbtstat](https://attack.mitre.org/software/S0102), and [route](https://attack.mitre.org/software/S0103).<br /><br />Adversaries may use the information from [System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br /><br />",
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
    "technique_description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as  [Ping](https://attack.mitre.org/software/S0097) or <code>net view</code> using [Net](https://attack.mitre.org/software/S0039). Adversaries may also use local host files (ex: <code>C:\\Windows\\System32\\Drivers\\etc\\hosts</code> or <code>/etc/hosts</code>) in order to discover the hostname to IP address mappings of remote systems. <br /><br />Specific to macOS, the <code>bonjour</code> protocol exists to discover additional Mac-based systems within the same broadcast domain.<br /><br />",
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
    "technique_description": "Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br /><br />Utilities and commands that acquire this information include <code>whoami</code>. In Mac and Linux, the currently logged in user can be identified with <code>w</code> and <code>who</code>.<br /><br />",
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
    "technique_description": "Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.<br /><br />Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.<br /><br />Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities.<br /><br />",
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
    "technique_description": "Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system. <br /><br />Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.<br /><br />",
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
    "technique_description": "Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. <br /><br />An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate.(Citation: Amazon AWS VPC Guide)(Citation: Microsoft Azure Virtual Network Overview)(Citation: Google VPC Overview)<br /><br />Utilities and commands that acquire this information include [netstat](https://attack.mitre.org/software/S0104), \"net use,\" and \"net session\" with [Net](https://attack.mitre.org/software/S0039). In Mac and Linux, [netstat](https://attack.mitre.org/software/S0104) and <code>lsof</code> can be used to list current connections. <code>who -a</code> and <code>w</code> can be used to show which users are currently logged in, similar to \"net session\".<br /><br />",
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
    "technique_description": "Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Adversaries may use the information from [Process Discovery](https://attack.mitre.org/techniques/T1057) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br /><br />In Windows environments, adversaries could obtain details on running processes using the [Tasklist](https://attack.mitre.org/software/S0057) utility via [cmd](https://attack.mitre.org/software/S0106) or <code>Get-Process</code> via [PowerShell](https://attack.mitre.org/techniques/T1059/001). Information about processes can also be extracted from the output of [Native API](https://attack.mitre.org/techniques/T1106) calls such as <code>CreateToolhelp32Snapshot</code>. In Mac and Linux, this is accomplished with the <code>ps</code> command. Adversaries may also opt to enumerate processes via /proc.<br /><br />",
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
    "technique_description": "Adversaries may attempt to find group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.<br /><br />",
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
    "technique_description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from [System Information Discovery](https://attack.mitre.org/techniques/T1082) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br /><br />Tools such as [Systeminfo](https://attack.mitre.org/software/S0096) can be used to gather detailed system information. A breakdown of system data can also be gathered through the macOS <code>systemsetup</code> command, but it requires administrative privileges.<br /><br />Infrastructure as a Service (IaaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine.(Citation: Amazon Describe Instance)(Citation: Google Instances Resource)(Citation: Microsoft Virutal Machine API)<br /><br />",
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
    "technique_description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br /><br />Many command shell utilities can be used to obtain this information. Examples include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>, and <code>locate</code>. (Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the [Native API](https://attack.mitre.org/techniques/T1106).<br /><br />",
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
    "technique_description": "Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior.<br /><br />",
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
    "technique_description": "Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.<br /><br />",
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
    "technique_description": "An adversary may gather the system time and/or time zone from a local or remote system. The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network. (Citation: MSDN System Time) (Citation: Technet Windows Time Service)<br /><br />System time information may be gathered in a number of ways, such as with [Net](https://attack.mitre.org/software/S0039) on Windows by performing <code>net time \\\\hostname</code> to gather the system time on a remote system. The victim's time zone may also be inferred from the current system time or gathered by using <code>w32tm /tz</code>. (Citation: Technet Windows Time Service) The information could be useful for performing other techniques, such as executing a file with a [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) (Citation: RSA EU12 They're Inside), or to discover locality information based on time zone to assist in victim targeting.<br /><br />",
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
    "technique_description": "Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network. <br /><br />File sharing over a Windows network occurs over the SMB protocol. (Citation: Wikipedia Shared Resource) (Citation: TechNet Shared Folder) [Net](https://attack.mitre.org/software/S0039) can be used to query a remote system for available shared drives using the <code>net view \\\\remotesystem</code> command. It can also be used to query shared drives on the local system using <code>net share</code>.<br /><br />",
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
    "technique_description": "Adversaries may attempt to access detailed information about the password policy used within an enterprise network. Password policies for networks are a way to enforce complex passwords that are difficult to guess or crack through [Brute Force](https://attack.mitre.org/techniques/T1110). This would help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).<br /><br />Password policies can be set and discovered on Windows, Linux, and macOS systems via various command shell utilities such as <code>net accounts (/domain)</code>, <code>Get-ADDefaultDomainPasswordPolicy</code>, <code>chage -l <username></code>, <code>cat /etc/pam.d/common-password</code>, and <code>pwpolicy getaccountpolicies</code>.(Citation: Superuser Linux Password Policies) (Citation: Jamf User Password Policies)<br /><br />",
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
    "technique_description": "Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.<br /><br />Browser bookmarks may also highlight additional targets after an adversary has access to valid credentials, especially [Credentials In Files](https://attack.mitre.org/techniques/T1552/001) associated with logins cached by a browser.<br /><br />Specific storage locations vary based on platform and/or application, but browser bookmarks are typically stored in local files/databases.<br /><br />",
    "technique_references": []
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
    "technique_description": "Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain.(Citation: Microsoft Trusts) Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct [SID-History Injection](https://attack.mitre.org/techniques/T1134/005), [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003), and [Kerberoasting](https://attack.mitre.org/techniques/T1558/003).(Citation: AdSecurity Forging Trust Tickets)(Citation: Harmj0y Domain Trusts) Domain trusts can be enumerated using the `DSEnumerateDomainTrusts()` Win32 API call, .NET methods, and LDAP.(Citation: Harmj0y Domain Trusts) The Windows utility [Nltest](https://attack.mitre.org/software/S0359) is known to be used by adversaries to enumerate domain trusts.(Citation: Microsoft Operation Wilysupply)<br /><br />",
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
    "technique_description": "Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from [Software Discovery](https://attack.mitre.org/techniques/T1518) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br /><br />Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable to [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068).<br /><br />",
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
    "technique_description": "An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Azure AD, etc. <br /><br />Adversaries may attempt to discover information about the services enabled throughout the environment. Azure tools and APIs, such as the Azure AD Graph API and Azure Resource Manager API, can enumerate resources and services, including applications, management groups, resources and policy definitions, and their relationships that are accessible by an identity.(Citation: Azure - Resource Manager API)(Citation: Azure AD Graph API)<br /><br />Stormspotter is an open source tool for enumerating and constructing a graph for Azure resources and services, and Pacu is an open source AWS exploitation framework that supports several methods for discovering cloud services.(Citation: Azure - Stormspotter)(Citation: GitHub Pacu)<br /><br />",
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
    "technique_description": "An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports.(Citation: Google Command Center Dashboard)<br /><br />Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API. This allows the adversary to gain information without making any API requests.<br /><br />",
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
    "technique_description": "An adversary may attempt to discover resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services.<br /><br />Cloud providers offer methods such as APIs and commands issued through CLIs to serve information about infrastructure. For example, AWS provides a <code>DescribeInstances</code> API within the Amazon EC2 API that can return information about one or more instances within an account, as well as the <code>ListBuckets</code> API that returns a list of all buckets owned by the authenticated sender of the request.(Citation: Amazon Describe Instance)(Citation: Amazon Describe Instances API) Similarly, GCP's Cloud SDK CLI provides the <code>gcloud compute instances list</code> command to list all Google Compute Engine instances in a project(Citation: Google Compute Instances), and Azure's CLI command <code>az vm list</code> lists details of virtual machines.(Citation: Microsoft AZ CLI)<br /><br />An adversary may enumerate resources using a compromised user's access keys to determine which are available to that user.(Citation: Expel IO Evil in AWS) The discovery of these available resources may help adversaries determine their next steps in the Cloud environment, such as establishing Persistence.(Citation: Mandiant M-Trends 2020) Unlike in [Cloud Service Discovery](https://attack.mitre.org/techniques/T1526), this technique focuses on the discovery of components of the provided services rather than the services themselves.<br /><br />",
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
  }
]
