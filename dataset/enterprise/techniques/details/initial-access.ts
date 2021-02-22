 [
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
    "technique_description": "Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.<br /><br />",
    "technique_references": []
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
    "technique_description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring [Application Access Token](https://attack.mitre.org/techniques/T1550/001).<br /><br />Multiple ways of delivering exploit code to a browser exist, including:<br /><br />* A legitimate website is compromised where adversaries have injected some form of malicious code such as JavaScript, iFrames, and cross-site scripting.<br /><br />* Malicious ads are paid for and served through legitimate ad providers.<br /><br />* Built-in web application interfaces are leveraged for the insertion of any other kind of object that can be used to display web content or contain a script that executes on the visiting client (e.g. forum posts, comments, and other user controllable web content).<br /><br />Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted attack is referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring.(Citation: Shadowserver Strategic Web Compromise)<br /><br />Typical drive-by compromise process:<br /><br />1. A user visits a website that is used to host the adversary controlled content.<br /><br />2. Scripts automatically execute, typically searching versions of the browser and plugins for a potentially vulnerable version. <br /><br />    * The user may be required to assist in this process by enabling scripting or active website components and ignoring warning dialog boxes.<br /><br />3. Upon finding a vulnerable version, exploit code is delivered to the browser.<br /><br />4. If exploitation is successful, then it will give the adversary code execution on the user's system unless other protections are in place.<br /><br />    * In some cases a second visit to the website after the initial scan is required before exploit code is delivered.<br /><br />Unlike [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), the focus of this technique is to exploit software on a client endpoint upon visiting a website. This will commonly give an adversary access to systems on the internal network instead of external systems that may be in a DMZ.<br /><br />Adversaries may also use compromised websites to deliver a user to a malicious application designed to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s, like OAuth tokens, to gain access to protected applications and information. These malicious applications have been delivered through popups on legitimate websites.(Citation: Volexity OceanLotus Nov 2017)<br /><br />",
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
    "technique_description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. The weakness in the system can be a bug, a glitch, or a design vulnerability. These applications are often websites, but can include databases (like SQL)(Citation: NVD CVE-2016-6662), standard services (like SMB(Citation: CIS Multiple SMB Vulnerabilities) or SSH), network device administration and management protocols (like SNMP and Smart Install(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)), and any other applications with Internet accessible open sockets, such as web servers and related services.(Citation: NVD CVE-2014-7169) Depending on the flaw being exploited this may include [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211). <br /><br />If an application is hosted on cloud-based infrastructure, then exploiting it may lead to compromise of the underlying instance. This can allow an adversary a path to access the cloud APIs or to take advantage of weak identity and access management policies.<br /><br />For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25)<br /><br />",
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
    "technique_description": "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.<br /><br />Supply chain compromise can take place at any stage of the supply chain including:<br /><br />* Manipulation of development tools<br /><br />* Manipulation of a development environment<br /><br />* Manipulation of source code repositories (public or private)<br /><br />* Manipulation of source code in open-source dependencies<br /><br />* Manipulation of software update/distribution mechanisms<br /><br />* Compromised/infected system images (multiple cases of removable media infected at the factory) (Citation: IBM Storwize) (Citation: Schneider Electric USB Malware) <br /><br />* Replacement of legitimate software with modified versions<br /><br />* Sales of modified/counterfeit products to legitimate distributors<br /><br />* Shipment interdiction<br /><br />While supply chain compromise can impact any component of hardware or software, attackers looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels. (Citation: Avast CCleaner3 2018) (Citation: Microsoft Dofoil 2018) (Citation: Command Five SK 2011) Targeting may be specific to a desired victim set (Citation: Symantec Elderwood Sept 2012) or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims. (Citation: Avast CCleaner3 2018) (Citation: Command Five SK 2011) Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency. (Citation: Trendmicro NPM Compromise)<br /><br />",
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
    "technique_description": "Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship exploits an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.<br /><br />Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments. Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise. As such, [Valid Accounts](https://attack.mitre.org/techniques/T1078) used by the other party for access to internal network systems may be compromised and used.<br /><br />",
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
    "technique_description": "Adversaries may introduce computer accessories, computers, or networking hardware into a system or network that can be used as a vector to gain access. While public references of usage by APT groups are scarce, many penetration testers leverage hardware additions for initial access. Commercial and open source products are leveraged with capabilities such as passive network tapping (Citation: Ossmann Star Feb 2011), man-in-the middle encryption breaking (Citation: Aleks Weapons Nov 2015), keystroke injection (Citation: Hak5 RubberDuck Dec 2016), kernel memory reading via DMA (Citation: Frisk DMA August 2016), adding new wireless access to an existing network (Citation: McMillan Pwn March 2012), and others.<br /><br />",
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
    "technique_description": "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.<br /><br />Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems or to gather credentials for use of [Valid Accounts](https://attack.mitre.org/techniques/T1078). Phishing may also be conducted via third-party services, like social media platforms.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/98.html",
        "description": "none",
        "external_id": "CAPEC-98"
      }
    ]
  }
]
