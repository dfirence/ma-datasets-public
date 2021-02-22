 [
  {
    "id": "attack-pattern--6151cbea-819b-455a-9fa6-99a1cc58797d",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1078.001",
    "technique": "Default Accounts",
    "tactic": "initial-access",
    "datasources": "authentication-logs|aws-cloudtrail-logs|process-monitoring|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems or default factory/provider set accounts on other types of systems, software, or devices.(Citation: Microsoft Local Accounts Feb 2019)<br /><br />Default accounts are not limited to client machines, rather also include accounts that are preset for equipment such as network devices and computer applications whether they are internal, open source, or commercial. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed or stolen [Private Keys](https://attack.mitre.org/techniques/T1552/004) or credential materials to legitimately connect to remote environments via [Remote Services](https://attack.mitre.org/techniques/T1021).(Citation: Metasploit SSH Module)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/70.html",
        "description": "none",
        "external_id": "CAPEC-70"
      },
      {
        "source_name": "Microsoft Local Accounts Feb 2019",
        "url": "https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts",
        "description": "Microsoft. (2018, December 9). Local Accounts. Retrieved February 11, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Metasploit SSH Module",
        "url": "https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/linux/ssh",
        "description": "undefined. (n.d.). Retrieved April 12, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--c3d4bdd9-2cfe-4a80-9d0c-07a29ecdce8f",
    "platform": "linux|macos|windows",
    "tid": "T1078.002",
    "technique": "Domain Accounts",
    "tactic": "initial-access",
    "datasources": "authentication-logs|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. (Citation: TechNet Credential Theft) Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.(Citation: Microsoft AD Accounts)<br /><br />Adversaries may compromise domain accounts, some with a high level of privileges, through various means such as [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) or password reuse, allowing access to privileged resources of the domain.<br /><br />",
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
        "source_name": "Microsoft AD Accounts",
        "url": "https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts",
        "description": "Microsoft. (2019, August 23). Active Directory Accounts. Retrieved March 13, 2020.",
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
    "id": "attack-pattern--fdc47f44-dd32-4b99-af5f-209f556f63c2",
    "platform": "linux|macos|windows",
    "tid": "T1078.003",
    "technique": "Local Accounts",
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
    "technique_description": "Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.<br /><br />Local Accounts may also be abused to elevate privileges and harvest credentials through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement. <br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--f232fa7a-025c-4d43-abc7-318e81a73d65",
    "platform": "aws|gcp|azure|saas|azure-ad|office-365",
    "tid": "T1078.004",
    "technique": "Cloud Accounts",
    "tactic": "initial-access",
    "datasources": "authentication-logs|aws-cloudtrail-logs|azure-activity-logs|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may obtain and abuse credentials of a cloud account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. In some cases, cloud accounts may be federated with traditional identity management system, such as Window Active Directory. (Citation: AWS Identity Federation)(Citation: Google Federating GC)(Citation: Microsoft Deploying AD Federation)<br /><br />Compromised credentials for cloud accounts can be used to harvest sensitive data from online storage accounts and databases. Access to cloud accounts can also be abused to gain Initial Access to a network by abusing a [Trusted Relationship](https://attack.mitre.org/techniques/T1199). Similar to [Domain Accounts](https://attack.mitre.org/techniques/T1078/002), compromise of federated cloud accounts may allow adversaries to more easily move laterally within an environment.<br /><br />",
    "technique_references": [
      {
        "source_name": "AWS Identity Federation",
        "url": "https://aws.amazon.com/identity/federation/",
        "description": "Amazon. (n.d.). Identity Federation in AWS. Retrieved March 13, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Google Federating GC",
        "url": "https://cloud.google.com/solutions/federating-gcp-with-active-directory-introduction",
        "description": "Google. (n.d.). Federating Google Cloud with Active Directory. Retrieved March 13, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Deploying AD Federation",
        "url": "https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/how-to-connect-fed-azure-adfs",
        "description": "Microsoft. (n.d.). Deploying Active Directory Federation Services in Azure. Retrieved March 13, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--191cc6af-1bb2-4344-ab5f-28e496638720",
    "platform": "linux|macos|windows",
    "tid": "T1195.001",
    "technique": "Compromise Software Dependencies and Development Tools",
    "tactic": "initial-access",
    "datasources": "file-monitoring|web-proxy",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly. Popular open source projects that are used as dependencies in many applications may be targeted as a means to add malicious code to users of the dependency. (Citation: Trendmicro NPM Compromise)  <br /><br />Targeting may be specific to a desired victim set or may be distributed to a broad set of consumers but only move on to additional tactics on specific victims. <br /><br />",
    "technique_references": [
      {
        "source_name": "Trendmicro NPM Compromise",
        "url": "https://www.trendmicro.com/vinfo/dk/security/news/cybercrime-and-digital-threats/hacker-infects-node-js-package-to-steal-from-bitcoin-wallets",
        "description": "Trendmicro. (2018, November 29). Hacker Infects Node.js Package to Steal from Bitcoin Wallets. Retrieved April 10, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--bd369cd9-abb8-41ce-b5bb-fff23ee86c00",
    "platform": "linux|macos|windows",
    "tid": "T1195.002",
    "technique": "Compromise Software Supply Chain",
    "tactic": "initial-access",
    "datasources": "file-monitoring|web-proxy",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise of software can take place in a number of ways, including manipulation of the application source code, manipulation of the update/distribution mechanism for that software, or replacing compiled releases with a modified version.<br /><br />Targeting may be specific to a desired victim set or may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.(Citation: Avast CCleaner3 2018) (Citation: Command Five SK 2011)  <br /><br />",
    "technique_references": [
      {
        "source_name": "Avast CCleaner3 2018",
        "url": "https://blog.avast.com/new-investigations-in-ccleaner-incident-point-to-a-possible-third-stage-that-had-keylogger-capacities",
        "description": "Avast Threat Intelligence Team. (2018, March 8). New investigations into the CCleaner incident point to a possible third stage that had keylogger capacities. Retrieved March 15, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Command Five SK 2011",
        "url": "https://www.commandfive.com/papers/C5_APT_SKHack.pdf",
        "description": "Command Five Pty Ltd. (2011, September). SK Hack by an Advanced Persistent Threat. Retrieved April 6, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--39131305-9282-45e4-ac3b-591d2d4fc3ef",
    "platform": "linux|macos|windows",
    "tid": "T1195.003",
    "technique": "Compromise Hardware Supply Chain",
    "tactic": "initial-access",
    "datasources": "bios|component-firmware|disk-forensics|efi",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise. By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer networks that may be difficult to detect and give the adversary a high degree of control over the system. Hardware backdoors may be inserted into various devices, such as servers, workstations, network infrastructure, or peripherals.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597",
    "platform": "macos|windows|linux",
    "tid": "T1566.001",
    "technique": "Spearphishing Attachment",
    "tactic": "initial-access",
    "datasources": "detonation-chamber|email-gateway|file-monitoring|mail-server|network-intrusion-detection-system|packet-capture",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.<br /><br />There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/163.html",
        "description": "none",
        "external_id": "CAPEC-163"
      }
    ]
  },
  {
    "id": "attack-pattern--2b742742-28c3-4e1b-bab7-8350d6300fa7",
    "platform": "linux|macos|windows|office-365|saas",
    "tid": "T1566.002",
    "technique": "Spearphishing Link",
    "tactic": "initial-access",
    "datasources": "detonation-chamber|dns-records|email-gateway|mail-server|packet-capture|ssl-tls-inspection|web-proxy",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. <br /><br />All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this case, the malicious emails contain links. Generally, the links will be accompanied by social engineering text and require the user to actively click or copy and paste a URL into a browser, leveraging [User Execution](https://attack.mitre.org/techniques/T1204). The visited website may compromise the web browser using an exploit, or the user will be prompted to download applications, documents, zip files, or even executables depending on the pretext for the email in the first place. Adversaries may also include links that are intended to interact directly with an email reader, including embedded images intended to exploit the end system directly or verify the receipt of an email (i.e. web bugs/web beacons). Links may also direct users to malicious applications  designed to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s, like OAuth tokens, in order to gain access to protected applications and information.(Citation: Trend Micro Pawn Storm OAuth 2017)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/163.html",
        "description": "none",
        "external_id": "CAPEC-163"
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
    "id": "attack-pattern--f6ad61ee-65f3-4bd0-a3f5-2f0accb36317",
    "platform": "linux|macos|windows",
    "tid": "T1566.003",
    "technique": "Spearphishing via Service",
    "tactic": "initial-access",
    "datasources": "anti-virus|ssl-tls-inspection|web-proxy",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems. Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of third party services rather than directly via enterprise email channels. <br /><br />All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services. These services are more likely to have a less-strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries will create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and software that's running in an environment. The adversary can then send malicious links or attachments through these services.<br /><br />A common example is to build rapport with a target via social media, then send content to a personal webmail service that the target uses on their work computer. This allows an adversary to bypass some email restrictions on the work account, and the target is more likely to open the file since it's something they were expecting. If the payload doesn't work as expected, the adversary can continue normal communications and troubleshoot with the target on how to get it working.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/163.html",
        "description": "none",
        "external_id": "CAPEC-163"
      }
    ]
  }
]
