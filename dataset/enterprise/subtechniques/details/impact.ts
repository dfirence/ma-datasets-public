export const IMPACT_SUBTECHNIQUE_DETAILS = [
  {
    "id": "attack-pattern--8c41090b-aa47-4331-986b-8c9a51a91103",
    "platform": "linux|macos|windows",
    "tid": "T1491.001",
    "technique": "Internal Defacement",
    "tactic": "impact",
    "datasources": "packet-capture|web-application-firewall-logs|web-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users. This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper.(Citation: Novetta Blockbuster) Disturbing or offensive images may be used as a part of [Internal Defacement](https://attack.mitre.org/techniques/T1491/001) in order to cause user discomfort, or to pressure compliance with accompanying messages. Since internally defacing systems exposes an adversary's presence, it often takes place after other intrusion goals have been accomplished.(Citation: Novetta Blockbuster Destructive Malware)<br /><br />",
    "technique_references": [
      {
        "source_name": "Novetta Blockbuster",
        "url": "https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf",
        "description": "Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Unraveling the Long Thread of the Sony Attack. Retrieved February 25, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Novetta Blockbuster Destructive Malware",
        "url": "https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf",
        "description": "Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Destructive Malware Report. Retrieved March 2, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0cfe31a7-81fc-472c-bc45-e2808d1066a3",
    "platform": "linux|macos|windows|aws|gcp|azure",
    "tid": "T1491.002",
    "technique": "External Defacement",
    "tactic": "impact",
    "datasources": "packet-capture|web-application-firewall-logs|web-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users. Externally-facing websites are a common victim of defacement; often targeted by adversary and hacktivist groups in order to push a political message or spread propaganda.(Citation: FireEye Cyber Threats to Media Industries)(Citation: Kevin Mandia Statement to US Senate Committee on Intelligence)(Citation: Anonymous Hackers Deface Russian Govt Site) [External Defacement](https://attack.mitre.org/techniques/T1491/002) may be used as a catalyst to trigger events, or as a response to actions taken by an organization or government. Similarly, website defacement may also be used as setup, or a precursor, for future attacks such as [Drive-by Compromise](https://attack.mitre.org/techniques/T1189).(Citation: Trend Micro Deep Dive Into Defacement)<br /><br />",
    "technique_references": [
      {
        "source_name": "FireEye Cyber Threats to Media Industries",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/ib-entertainment.pdf",
        "description": "FireEye. (n.d.). Retrieved April 19, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Kevin Mandia Statement to US Senate Committee on Intelligence",
        "url": "https://www.intelligence.senate.gov/sites/default/files/documents/os-kmandia-033017.pdf",
        "description": "Kevin Mandia. (2017, March 30). Prepared Statement of Kevin Mandia, CEO of FireEye, Inc. before the United States Senate Select Committee on Intelligence. Retrieved April 19, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Anonymous Hackers Deface Russian Govt Site",
        "url": "https://torrentfreak.com/anonymous-hackers-deface-russian-govt-site-to-protest-web-blocking-nsfw-180512/",
        "description": "Andy. (2018, May 12). ‘Anonymous’ Hackers Deface Russian Govt. Site to Protest Web-Blocking (NSFW). Retrieved April 19, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Trend Micro Deep Dive Into Defacement",
        "url": "https://documents.trendmicro.com/assets/white_papers/wp-a-deep-dive-into-defacement.pdf",
        "description": "Marco Balduzzi, Ryan Flores, Lion Gu, Federico Maggi, Vincenzo Ciancaglini, Roel Reyes, Akira Urano. (n.d.). A Deep Dive into Defacement: How Geopolitical Events Trigger Web Attacks. Retrieved April 19, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0bda01d5-4c1d-4062-8ee2-6872334383c3",
    "platform": "linux|macos|windows|aws|gcp|azure-ad|saas|azure|office-365",
    "tid": "T1498.001",
    "technique": "Direct Network Flood",
    "tactic": "impact",
    "datasources": "netflow-enclave-netflow|network-device-logs|network-intrusion-detection-system|network-protocol-analysis|sensor-health-and-status",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. [Direct Network Flood](https://attack.mitre.org/techniques/T1498/001) are when one or more systems are used to send a high-volume of network packets towards the targeted service's network. Almost any network protocol may be used for flooding. Stateless protocols such as UDP or ICMP are commonly used but stateful protocols such as TCP can be used as well.<br /><br />Botnets are commonly used to conduct network flooding attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global Internet. Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack. In some of the worst cases for distributed DoS (DDoS), so many systems are used to generate the flood that each one only needs to send out a small amount of traffic to produce enough volume to saturate the target network. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS flooding attacks, such as the 2012 series of incidents that targeted major US banks.(Citation: USNYAG IranianBotnet March 2016)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/125.html",
        "description": "none",
        "external_id": "CAPEC-125"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/486.html",
        "description": "none",
        "external_id": "CAPEC-486"
      },
      {
        "source_name": "USNYAG IranianBotnet March 2016",
        "url": "https://www.justice.gov/opa/pr/seven-iranians-working-islamic-revolutionary-guard-corps-affiliated-entities-charged",
        "description": "Preet Bharara, US Attorney. (2016, March 24). Retrieved April 23, 2019.",
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
    "id": "attack-pattern--36b2a1d7-e09e-49bf-b45e-477076c2ec01",
    "platform": "macos|windows|linux|aws|office-365|azure-ad|gcp|azure|saas",
    "tid": "T1498.002",
    "technique": "Reflection Amplification",
    "tactic": "impact",
    "datasources": "netflow-enclave-netflow|network-device-logs|network-intrusion-detection-system|network-protocol-analysis|sensor-health-and-status",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to cause a denial of service by reflecting a high-volume of network traffic to a target. This type of Network DoS takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed source IP address. This third-party server is commonly termed a reflector. An adversary accomplishes a reflection attack by sending packets to reflectors with the spoofed address of the victim. Similar to Direct Network Floods, more than one system may be used to conduct the attack, or a botnet may be used. Likewise, one or more reflector may be used to focus traffic on the target.(Citation: Cloudflare ReflectionDoS May 2017)<br /><br />Reflection attacks often take advantage of protocols with larger responses than requests in order to amplify their traffic, commonly known as a Reflection Amplification attack. Adversaries may be able to generate an increase in volume of attack traffic that is several orders of magnitude greater than the requests sent to the amplifiers. The extent of this increase will depending upon many variables, such as the protocol in question, the technique used, and the amplifying servers that actually produce the amplification in attack volume. Two prominent protocols that have enabled Reflection Amplification Floods are DNS(Citation: Cloudflare DNSamplficationDoS) and NTP(Citation: Cloudflare NTPamplifciationDoS), though the use of several others in the wild have been documented.(Citation: Arbor AnnualDoSreport Jan 2018)  In particular, the memcache protocol showed itself to be a powerful protocol, with amplification sizes up to 51,200 times the requesting packet.(Citation: Cloudflare Memcrashed Feb 2018)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/490.html",
        "description": "none",
        "external_id": "CAPEC-490"
      },
      {
        "source_name": "Cloudflare ReflectionDoS May 2017",
        "url": "https://blog.cloudflare.com/reflections-on-reflections/",
        "description": "Marek Majkowsk, Cloudflare. (2017, May 24). Reflections on reflection (attacks). Retrieved April 23, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Cloudflare DNSamplficationDoS",
        "url": "https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/",
        "description": "Cloudflare. (n.d.). What is a DNS amplification attack?. Retrieved April 23, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Cloudflare NTPamplifciationDoS",
        "url": "https://www.cloudflare.com/learning/ddos/ntp-amplification-ddos-attack/",
        "description": "Cloudflare. (n.d.). What is a NTP amplificaiton attack?. Retrieved April 23, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Arbor AnnualDoSreport Jan 2018",
        "url": "https://pages.arbornetworks.com/rs/082-KNA-087/images/13th_Worldwide_Infrastructure_Security_Report.pdf",
        "description": "Philippe Alcoy, Steinthor Bjarnason, Paul Bowen, C.F. Chui, Kirill Kasavchnko, and Gary Sockrider of Netscout Arbor. (2018, January). Insight into the Global Threat Landscape - Netscout Arbor's 13th Annual Worldwide Infrastructure Security Report. Retrieved April 22, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Cloudflare Memcrashed Feb 2018",
        "url": "https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/",
        "description": "Marek Majkowski of Cloudflare. (2018, February 27). Memcrashed - Major amplification attacks from UDP port 11211. Retrieved April 18, 2019.",
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
    "id": "attack-pattern--0df05477-c572-4ed6-88a9-47c581f548f7",
    "platform": "linux|macos|windows",
    "tid": "T1499.001",
    "technique": "OS Exhaustion Flood",
    "tactic": "impact",
    "datasources": "netflow-enclave-netflow|network-device-logs|network-intrusion-detection-system|ssl-tls-inspection",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may target the operating system (OS) for a DoS attack, since the (OS) is responsible for managing the finite resources on a system. These attacks do not need to exhaust the actual resources on a system since they can simply exhaust the limits that an OS self-imposes to prevent the entire system from being overwhelmed by excessive demands on its capacity.<br /><br />Different ways to achieve this exist, including TCP state-exhaustion attacks such as SYN floods and ACK floods.(Citation: Arbor AnnualDoSreport Jan 2018) With SYN floods, excessive amounts of SYN packets are sent, but the 3-way TCP handshake is never completed. Because each OS has a maximum number of concurrent TCP connections that it will allow, this can quickly exhaust the ability of the system to receive new requests for TCP connections, thus preventing access to any TCP service provided by the server.(Citation: Cloudflare SynFlood)<br /><br />ACK floods leverage the stateful nature of the TCP protocol. A flood of ACK packets are sent to the target. This forces the OS to search its state table for a related TCP connection that has already been established. Because the ACK packets are for connections that do not exist, the OS will have to search the entire state table to confirm that no match exists. When it is necessary to do this for a large flood of packets, the computational requirements can cause the server to become sluggish and/or unresponsive, due to the work it must do to eliminate the rogue ACK packets. This greatly reduces the resources available for providing the targeted service.(Citation: Corero SYN-ACKflood)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/469.html",
        "description": "none",
        "external_id": "CAPEC-469"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/482.html",
        "description": "none",
        "external_id": "CAPEC-482"
      },
      {
        "source_name": "Arbor AnnualDoSreport Jan 2018",
        "url": "https://pages.arbornetworks.com/rs/082-KNA-087/images/13th_Worldwide_Infrastructure_Security_Report.pdf",
        "description": "Philippe Alcoy, Steinthor Bjarnason, Paul Bowen, C.F. Chui, Kirill Kasavchnko, and Gary Sockrider of Netscout Arbor. (2018, January). Insight into the Global Threat Landscape - Netscout Arbor's 13th Annual Worldwide Infrastructure Security Report. Retrieved April 22, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Cloudflare SynFlood",
        "url": "https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/",
        "description": "Cloudflare. (n.d.). What is a SYN flood attack?. Retrieved April 22, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Corero SYN-ACKflood",
        "url": "https://www.corero.com/resources/ddos-attack-types/syn-flood-ack.html",
        "description": "Corero. (n.d.). What is a SYN-ACK Flood Attack?. Retrieved April 22, 2019.",
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
    "id": "attack-pattern--38eb0c22-6caf-46ce-8869-5964bd735858",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1499.002",
    "technique": "Service Exhaustion Flood",
    "tactic": "impact",
    "datasources": "netflow-enclave-netflow|network-device-logs|network-intrusion-detection-system|ssl-tls-inspection|web-application-firewall-logs|web-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may target the different network services provided by systems to conduct a DoS. Adversaries often target DNS and web services, however others have been targeted as well.(Citation: Arbor AnnualDoSreport Jan 2018) Web server software can be attacked through a variety of means, some of which apply generally while others are specific to the software being used to provide the service.<br /><br />One example of this type of attack is known as a simple HTTP flood, where an adversary sends a large number of HTTP requests to a web server to overwhelm it and/or an application that runs on top of it. This flood relies on raw volume to accomplish the objective, exhausting any of the various resources required by the victim software to provide the service.(Citation: Cloudflare HTTPflood)<br /><br />Another variation, known as a SSL renegotiation attack, takes advantage of a protocol feature in SSL/TLS. The SSL/TLS protocol suite includes mechanisms for the client and server to agree on an encryption algorithm to use for subsequent secure connections. If SSL renegotiation is enabled, a request can be made for renegotiation of the crypto algorithm. In a renegotiation attack, the adversary establishes a SSL/TLS connection and then proceeds to make a series of renegotiation requests. Because the cryptographic renegotiation has a meaningful cost in computation cycles, this can cause an impact to the availability of the service when done in volume.(Citation: Arbor SSLDoS April 2012)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/488.html",
        "description": "none",
        "external_id": "CAPEC-488"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/489.html",
        "description": "none",
        "external_id": "CAPEC-489"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/528.html",
        "description": "none",
        "external_id": "CAPEC-528"
      },
      {
        "source_name": "Arbor AnnualDoSreport Jan 2018",
        "url": "https://pages.arbornetworks.com/rs/082-KNA-087/images/13th_Worldwide_Infrastructure_Security_Report.pdf",
        "description": "Philippe Alcoy, Steinthor Bjarnason, Paul Bowen, C.F. Chui, Kirill Kasavchnko, and Gary Sockrider of Netscout Arbor. (2018, January). Insight into the Global Threat Landscape - Netscout Arbor's 13th Annual Worldwide Infrastructure Security Report. Retrieved April 22, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Cloudflare HTTPflood",
        "url": "https://www.cloudflare.com/learning/ddos/http-flood-ddos-attack/",
        "description": "Cloudflare. (n.d.). What is an HTTP flood DDoS attack?. Retrieved April 22, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Arbor SSLDoS April 2012",
        "url": "https://www.netscout.com/blog/asert/ddos-attacks-ssl-something-old-something-new",
        "description": "ASERT Team, Netscout Arbor. (2012, April 24). DDoS Attacks on SSL: Something Old, Something New. Retrieved April 22, 2019.",
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
    "id": "attack-pattern--18cffc21-3260-437e-80e4-4ab8bf2ba5e9",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1499.003",
    "technique": "Application Exhaustion Flood",
    "tactic": "impact",
    "datasources": "network-device-logs|network-intrusion-detection-system|ssl-tls-inspection|web-application-firewall-logs|web-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may target resource intensive features of web applications to cause a denial of service (DoS). Specific features in web applications may be highly resource intensive. Repeated requests to those features may be able to exhaust system resources and deny access to the application or the server itself. (Citation: Arbor AnnualDoSreport Jan 2018)<br /><br />",
    "technique_references": [
      {
        "source_name": "Arbor AnnualDoSreport Jan 2018",
        "url": "https://pages.arbornetworks.com/rs/082-KNA-087/images/13th_Worldwide_Infrastructure_Security_Report.pdf",
        "description": "Philippe Alcoy, Steinthor Bjarnason, Paul Bowen, C.F. Chui, Kirill Kasavchnko, and Gary Sockrider of Netscout Arbor. (2018, January). Insight into the Global Threat Landscape - Netscout Arbor's 13th Annual Worldwide Infrastructure Security Report. Retrieved April 22, 2019.",
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
    "id": "attack-pattern--2bee5ffb-7a7a-4119-b1f2-158151b19ac0",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1499.004",
    "technique": "Application or System Exploitation",
    "tactic": "impact",
    "datasources": "network-device-logs|network-intrusion-detection-system|ssl-tls-inspection|web-application-firewall-logs|web-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. (Citation: Sucuri BIND9 August 2015) Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent DoS condition.<br /><br />",
    "technique_references": [
      {
        "source_name": "Sucuri BIND9 August 2015",
        "url": "https://blog.sucuri.net/2015/08/bind9-denial-of-service-exploit-in-the-wild.html",
        "description": "Cid, D.. (2015, August 2). BIND9 – Denial of Service Exploit in the Wild. Retrieved April 26, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--fb640c43-aa6b-431e-a961-a279010424ac",
    "platform": "linux|macos|windows",
    "tid": "T1561.001",
    "technique": "Disk Content Wipe",
    "tactic": "impact",
    "datasources": "kernel-drivers|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources.<br /><br />Adversaries may partially or completely overwrite the contents of a storage device rendering the data irrecoverable through the storage interface.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Destructive Malware)(Citation: DOJ Lazarus Sony 2018) Instead of wiping specific disk structures or files, adversaries with destructive intent may wipe arbitrary portions of disk content. To wipe disk content, adversaries may acquire direct access to the hard drive in order to overwrite arbitrarily sized portions of disk with random data.(Citation: Novetta Blockbuster Destructive Malware) Adversaries have been observed leveraging third-party drivers like [RawDisk](https://attack.mitre.org/software/S0364) to directly access disk content.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Destructive Malware) This behavior is distinct from [Data Destruction](https://attack.mitre.org/techniques/T1485) because sections of the disk are erased instead of individual files.<br /><br />To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disk content may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Novetta Blockbuster Destructive Malware)<br /><br />",
    "technique_references": [
      {
        "source_name": "Novetta Blockbuster",
        "url": "https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf",
        "description": "Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Unraveling the Long Thread of the Sony Attack. Retrieved February 25, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Novetta Blockbuster Destructive Malware",
        "url": "https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf",
        "description": "Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Destructive Malware Report. Retrieved March 2, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "DOJ Lazarus Sony 2018",
        "url": "https://www.justice.gov/opa/press-release/file/1092091/download",
        "description": "Department of Justice. (2018, September 6). Criminal Complaint - United States of America v. PARK JIN HYOK. Retrieved March 29, 2019.",
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
    "id": "attack-pattern--0af0ca99-357d-4ba1-805f-674fdfb7bef9",
    "platform": "linux|macos|windows",
    "tid": "T1561.002",
    "technique": "Disk Structure Wipe",
    "tactic": "impact",
    "datasources": "kernel-drivers|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system; targeting specific critical systems or in large numbers in a network to interrupt availability to system and network resources. <br /><br />Adversaries may attempt to render the system unable to boot by overwriting critical data located in structures such as the master boot record (MBR) or partition table.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018) The data contained in disk structures may include the initial executable code for loading an operating system or the location of the file system partitions on disk. If this information is not present, the computer will not be able to load an operating system during the boot process, leaving the computer unavailable. [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) may be performed in isolation, or along with [Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) if all sectors of a disk are wiped.<br /><br />To maximize impact on the target organization, malware designed for destroying disk structures may have worm-like features to propagate across a network by leveraging other techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)<br /><br />",
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
        "source_name": "Microsoft Sysmon v6 May 2017",
        "url": "https://docs.microsoft.com/sysinternals/downloads/sysmon",
        "description": "Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1cfcb312-b8d7-47a4-b560-4b16cc677292",
    "platform": "linux|macos|windows",
    "tid": "T1565.001",
    "technique": "Stored Data Manipulation",
    "tactic": "impact",
    "datasources": "application-logs|file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may insert, delete, or manipulate data at rest in order to manipulate external outcomes or hide activity.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making.<br /><br />Stored data could include a variety of file formats, such as Office files, databases, stored emails, and custom file formats. The type of modification and the impact it will have depends on the type of data as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.<br /><br />",
    "technique_references": [
      {
        "source_name": "FireEye APT38 Oct 2018",
        "url": "https://content.fireeye.com/apt/rpt-apt38",
        "description": "FireEye. (2018, October 03). APT38: Un-usual Suspects. Retrieved November 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "DOJ Lazarus Sony 2018",
        "url": "https://www.justice.gov/opa/press-release/file/1092091/download",
        "description": "Department of Justice. (2018, September 6). Criminal Complaint - United States of America v. PARK JIN HYOK. Retrieved March 29, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d0613359-5781-4fd2-b5be-c269270be1f6",
    "platform": "linux|macos|windows",
    "tid": "T1565.002",
    "technique": "Transmitted Data Manipulation",
    "tactic": "impact",
    "datasources": "network-protocol-analysis|packet-capture",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating transmitted data, adversaries may attempt to affect a business process, organizational understanding, and decision making.<br /><br />Manipulation may be possible over a network connection or between system processes where there is an opportunity deploy a tool that will intercept and change information. The type of modification and the impact it will have depends on the target transmission mechanism as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.<br /><br />",
    "technique_references": [
      {
        "source_name": "FireEye APT38 Oct 2018",
        "url": "https://content.fireeye.com/apt/rpt-apt38",
        "description": "FireEye. (2018, October 03). APT38: Un-usual Suspects. Retrieved November 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "DOJ Lazarus Sony 2018",
        "url": "https://www.justice.gov/opa/press-release/file/1092091/download",
        "description": "Department of Justice. (2018, September 6). Criminal Complaint - United States of America v. PARK JIN HYOK. Retrieved March 29, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--32ad5c86-2bcf-47d8-8fdc-d7f3d79a7490",
    "platform": "linux|macos|windows",
    "tid": "T1565.003",
    "technique": "Runtime Data Manipulation",
    "tactic": "impact",
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
    "technique_description": "Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating runtime data, adversaries may attempt to affect a business process, organizational understanding, and decision making.<br /><br />Adversaries may alter application binaries used to display data in order to cause runtime manipulations. Adversaries may also conduct [Change Default File Association](https://attack.mitre.org/techniques/T1546/001) and [Masquerading](https://attack.mitre.org/techniques/T1036) to cause a similar effect. The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.<br /><br />",
    "technique_references": [
      {
        "source_name": "FireEye APT38 Oct 2018",
        "url": "https://content.fireeye.com/apt/rpt-apt38",
        "description": "FireEye. (2018, October 03). APT38: Un-usual Suspects. Retrieved November 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "DOJ Lazarus Sony 2018",
        "url": "https://www.justice.gov/opa/press-release/file/1092091/download",
        "description": "Department of Justice. (2018, September 6). Criminal Complaint - United States of America v. PARK JIN HYOK. Retrieved March 29, 2019.",
        "external_id": "none"
      }
    ]
  }
]
