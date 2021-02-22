 [
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
    "technique_description": "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018)(Citation: Talos Olympic Destroyer 2018) Common operating system file deletion commands such as <code>del</code> and <code>rm</code> often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from [Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) and [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) because individual files are destroyed rather than sections of a storage disk or the disk's logical structure.<br /><br />Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable.(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018) In some cases politically oriented image files have been used to overwrite data.(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)<br /><br />To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware designed for destroying data may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Talos Olympic Destroyer 2018)<br /><br />",
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
    "technique_description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted.(Citation: US-CERT Ransomware 2016)(Citation: FireEye WannaCry 2017)(Citation: US-CERT NotPetya 2017)(Citation: US-CERT SamSam 2018) In the case of ransomware, it is typical that common user files like Office documents, PDFs, images, videos, audio, text, and source code files will be encrypted. In some cases, adversaries may encrypt critical system files, disk partitions, and the MBR.(Citation: US-CERT NotPetya 2017)<br /><br />To maximize impact on the target organization, malware designed for encrypting data may have worm-like features to propagate across a network by leveraging other attack techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: FireEye WannaCry 2017)(Citation: US-CERT NotPetya 2017)<br /><br />",
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
    "technique_description": "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.(Citation: Talos Olympic Destroyer 2018)(Citation: Novetta Blockbuster) <br /><br />Adversaries may accomplish this by disabling individual services of high importance to an organization, such as <code>MSExchangeIS</code>, which will make Exchange content inaccessible (Citation: Novetta Blockbuster). In some cases, adversaries may stop or disable many or all services to render systems unusable.(Citation: Talos Olympic Destroyer 2018) Services may not allow for modification of their data stores while running. Adversaries may stop services in order to conduct [Data Destruction](https://attack.mitre.org/techniques/T1485) or [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) on the data stores of services like Exchange and SQL Server.(Citation: SecureWorks WannaCry Analysis)<br /><br />",
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
    "technique_description": "Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017) Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features. Adversaries may disable or delete system recovery features to augment the effects of [Data Destruction](https://attack.mitre.org/techniques/T1485) and [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486).(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017)<br /><br />A number of native Windows utilities have been used by adversaries to disable or delete system recovery features:<br /><br />* <code>vssadmin.exe</code> can be used to delete all volume shadow copies on a system - <code>vssadmin.exe delete shadows /all /quiet</code><br /><br />* [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) can be used to delete volume shadow copies - <code>wmic shadowcopy delete</code><br /><br />* <code>wbadmin.exe</code> can be used to delete the Windows Backup Catalog - <code>wbadmin.exe delete catalog -quiet</code><br /><br />* <code>bcdedit.exe</code> can be used to disable automatic Windows recovery features by modifying boot configuration data - <code>bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no</code><br /><br />",
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
    "technique_description": "Adversaries may modify visual content available internally or externally to an enterprise network. Reasons for [Defacement](https://attack.mitre.org/techniques/T1491) include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. Disturbing or offensive images may be used as a part of [Defacement](https://attack.mitre.org/techniques/T1491) in order to cause user discomfort, or to pressure compliance with accompanying messages. <br /><br />",
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
    "technique_description": "Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot.(Citation: Symantec Chernobyl W95.CIH) Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices could include the motherboard, hard drive, or video cards.<br /><br />",
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
    "technique_description": "Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability. <br /><br />One common purpose for Resource Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive.(Citation: Kaspersky Lazarus Under The Hood Blog 2017) Servers and cloud-based(Citation: CloudSploit - Unused AWS Regions) systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining.<br /><br />",
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
    "technique_description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications. Adversaries have been observed conducting network DoS attacks for political purposes(Citation: FireEye OpPoisonedHandover February 2016) and to support other malicious activities, including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS October 2014)<br /><br />A Network DoS will occur when the bandwidth capacity of the network connection to a system is exhausted due to the volume of malicious traffic directed at the resource or the network connections and network devices the resource relies on. For example, an adversary may send 10Gbps of traffic to a server that is hosted by a network with a 1Gbps connection to the internet. This traffic can be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS).<br /><br />To perform Network DoS attacks several aspects apply to multiple methods, including IP address spoofing, and botnets.<br /><br />Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection. This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.<br /><br />For DoS attacks targeting the hosting system directly, see [Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499).<br /><br />",
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
    "technique_description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition. Example services include websites, email services, DNS, and web-based applications. Adversaries have been observed conducting DoS attacks for political purposes(Citation: FireEye OpPoisonedHandover February 2016) and to support other malicious activities, including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS October 2014)<br /><br />An Endpoint DoS denies the availability of a service without saturating the network used to provide access to the service. Adversaries can target various layers of the application stack that is hosted on the system used to provide the service. These layers include the Operating Systems (OS), server applications such as web servers, DNS servers, databases, and the (typically web-based) applications that sit on top of them. Attacking each layer requires different techniques that take advantage of bottlenecks that are unique to the respective components. A DoS attack may be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS).<br /><br />To perform DoS attacks against endpoint resources, several aspects apply to multiple methods, including IP address spoofing and botnets.<br /><br />Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection. This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices.<br /><br />Botnets are commonly used to conduct DDoS attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global internet. Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack. In some of the worst cases for DDoS, so many systems are used to generate requests that each one only needs to send out a small amount of traffic to produce enough volume to exhaust the target's resources. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS attacks, such as the 2012 series of incidents that targeted major US banks.(Citation: USNYAG IranianBotnet March 2016)<br /><br />In cases where traffic manipulation is used, there may be points in the the global network (such as high traffic gateway routers) where packets can be altered and cause legitimate clients to execute code that directs network packets toward a target in high volume. This type of capability was previously used for the purposes of web censorship where client HTTP traffic was modified to include a reference to JavaScript that generated the DDoS code to overwhelm target web servers.(Citation: ArsTechnica Great Firewall of China)<br /><br />For attacks attempting to saturate the providing network, see [Network Denial of Service](https://attack.mitre.org/techniques/T1498).<br /><br />",
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
    "technique_description": "Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer.(Citation: Microsoft Shutdown Oct 2017) Shutting down or rebooting systems may disrupt access to computer resources for legitimate users.<br /><br />Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) or [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490), to hasten the intended effects on system availability.(Citation: Talos Nyetya June 2017)(Citation: Talos Olympic Destroyer 2018)<br /><br />",
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
    "technique_description": "Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts.<br /><br />Adversaries may also subsequently log off and/or reboot boxes to set malicious changes into place.(Citation: CarbonBlack LockerGoga 2019)(Citation: Unit42 LockerGoga 2019)<br /><br />",
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
    "technique_description": "Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted.<br /><br />To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disks may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Novetta Blockbuster Destructive Malware)<br /><br />",
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
    "technique_description": "Adversaries may insert, delete, or manipulate data in order to manipulate external outcomes or hide activity. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.<br /><br />The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.<br /><br />",
    "technique_references": []
  }
]
