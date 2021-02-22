 [
  {
    "id": "attack-pattern--ad255bfe-a9e6-4b52-a258-8d3462abe842",
    "platform": "linux|macos|windows",
    "tid": "T1001",
    "technique": "Data Obfuscation",
    "tactic": "command-and-control",
    "datasources": "network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1001.001",
      "T1001.002",
      "T1001.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols. <br /><br />",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f24faf46-3b26-4dbb-98f2-63460498e433",
    "platform": "linux|windows|macos",
    "tid": "T1008",
    "technique": "Fallback Channels",
    "tactic": "command-and-control",
    "datasources": "malware-reverse-engineering|netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.<br /><br />",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--355be19c-ffc9-46d5-8d50-d6a036c675b6",
    "platform": "linux|macos|windows",
    "tid": "T1071",
    "technique": "Application Layer Protocol",
    "tactic": "command-and-control",
    "datasources": "dns-records|netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1071.001",
      "T1071.002",
      "T1071.003",
      "T1071.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. <br /><br />Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, or DNS. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP. <br /><br />",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--731f4f55-b6d0-41d1-a7a9-072a66389aea",
    "platform": "linux|macos|windows|network",
    "tid": "T1090",
    "technique": "Proxy",
    "tactic": "command-and-control",
    "datasources": "netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network|ssl-tls-inspection",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1090.001",
      "T1090.002",
      "T1090.003",
      "T1090.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connections, provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. Adversaries may chain together multiple proxies to further disguise the source of malicious traffic.<br /><br />Adversaries can also take advantage of routing schemes in Content Delivery Networks (CDNs) to proxy command and control traffic.<br /><br />",
    "technique_references": [
      {
        "source_name": "Trend Micro APT Attack Tools",
        "url": "http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/",
        "description": "Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--64196062-5210-42c3-9a02-563a0d1797ef",
    "platform": "linux|macos|windows",
    "tid": "T1092",
    "technique": "Communication Through Removable Media",
    "tactic": "command-and-control",
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
    "technique_description": "Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091). Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--c21d5a77-d422-4a69-acd7-2c53c1faa34b",
    "platform": "windows|linux|macos|network",
    "tid": "T1095",
    "technique": "Non-Application Layer Protocol",
    "tactic": "command-and-control",
    "datasources": "host-network-interface|netflow-enclave-netflow|network-intrusion-detection-system|network-protocol-analysis|packet-capture|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive.(Citation: Wikipedia OSI) Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).<br /><br />ICMP communication between hosts is one example.(Citation: Cisco Synful Knock Evolution)<br /><br /> Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts; (Citation: Microsoft ICMP) however, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications.<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia OSI",
        "url": "http://en.wikipedia.org/wiki/List_of_network_protocols_%28OSI_model%29",
        "description": "Wikipedia. (n.d.). List of network protocols (OSI model). Retrieved December 4, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Synful Knock Evolution",
        "url": "https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices",
        "description": "Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft ICMP",
        "url": "http://support.microsoft.com/KB/170292",
        "description": "Microsoft. (n.d.). Internet Control Message Protocol (ICMP) Basics. Retrieved December 1, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Blog Legacy Device Attacks",
        "url": "https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954",
        "description": "Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--830c9528-df21-472c-8c14-a036bf17d665",
    "platform": "linux|macos|windows",
    "tid": "T1102",
    "technique": "Web Service",
    "tactic": "command-and-control",
    "datasources": "host-network-interface|netflow-enclave-netflow|network-protocol-analysis|packet-capture|ssl-tls-inspection",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1102.001",
      "T1102.002",
      "T1102.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.<br /><br />Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).<br /><br />",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--84e02621-8fdf-470f-bd58-993bb6a89d91",
    "platform": "linux|macos|windows",
    "tid": "T1104",
    "technique": "Multi-Stage Channels",
    "tactic": "command-and-control",
    "datasources": "netflow-enclave-netflow|network-device-logs|network-protocol-analysis|packet-capture|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.<br /><br />Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files. A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features.<br /><br />The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or [Fallback Channels](https://attack.mitre.org/techniques/T1008) in case the original first-stage communication path is discovered and blocked.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add",
    "platform": "linux|macos|windows",
    "tid": "T1105",
    "technique": "Ingress Tool Transfer",
    "tactic": "command-and-control",
    "datasources": "file-monitoring|netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-command-line-parameters|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.<br /><br />",
    "technique_references": [
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cc7b8c4e-9be0-47ca-b0bb-83915ec3ee2f",
    "platform": "linux|macos|windows",
    "tid": "T1132",
    "technique": "Data Encoding",
    "tactic": "command-and-control",
    "datasources": "network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1132.001",
      "T1132.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system. Use of data encoding may adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, or other binary-to-text and character encoding systems.(Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some data encoding systems may also result in data compression, such as gzip.<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia Binary-to-text Encoding",
        "url": "https://en.wikipedia.org/wiki/Binary-to-text_encoding",
        "description": "Wikipedia. (2016, December 26). Binary-to-text encoding. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Wikipedia Character Encoding",
        "url": "https://en.wikipedia.org/wiki/Character_encoding",
        "description": "Wikipedia. (2017, February 19). Character Encoding. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--451a9977-d255-43c9-b431-66de80130c8c",
    "platform": "linux|macos|windows|network",
    "tid": "T1205",
    "technique": "Traffic Signaling",
    "tactic": "command-and-control",
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
    "id": "attack-pattern--4061e78c-1284-44b4-9116-73e4ac3912f7",
    "platform": "linux|windows|macos",
    "tid": "T1219",
    "technique": "Remote Access Software",
    "tactic": "command-and-control",
    "datasources": "network-intrusion-detection-system|network-protocol-analysis|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks. These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment. Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)<br /><br />Remote access tools may be established and used post-compromise as alternate communications channel for redundant access or as a way to establish an interactive remote desktop session with the target system. They may also be used as a component of malware to establish a reverse connection or back-connect to a service or adversary controlled system.<br /><br />Admin tools such as TeamViewer have been used by several groups targeting institutions in countries of interest to the Russian state and criminal campaigns. (Citation: CrowdStrike 2015 Global Threat Report) (Citation: CrySyS Blog TeamSpy)<br /><br />",
    "technique_references": [
      {
        "source_name": "Symantec Living off the Land",
        "url": "https://www.symantec.com/content/dam/symantec/docs/security-center/white-papers/istr-living-off-the-land-and-fileless-attack-techniques-en.pdf",
        "description": "Wueest, C., Anand, H. (2017, July). Living off the land and fileless attack techniques. Retrieved April 10, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "CrowdStrike 2015 Global Threat Report",
        "url": "https://go.crowdstrike.com/rs/281-OBQ-266/images/15GlobalThreatReport.pdf",
        "description": "CrowdStrike Intelligence. (2016). 2015 Global Threat Report. Retrieved April 11, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "CrySyS Blog TeamSpy",
        "url": "https://blog.crysys.hu/2013/03/teamspy/",
        "description": "CrySyS Lab. (2013, March 20). TeamSpy – Obshie manevri. Ispolzovat’ tolko s razreshenija S-a. Retrieved April 11, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7bd9c723-2f78-4309-82c5-47cad406572b",
    "platform": "linux|macos|windows",
    "tid": "T1568",
    "technique": "Dynamic Resolution",
    "tactic": "command-and-control",
    "datasources": "dns-records|ssl-tls-inspection|web-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1568.001",
      "T1568.002",
      "T1568.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications. These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control.<br /><br />Adversaries may use dynamic resolution for the purpose of [Fallback Channels](https://attack.mitre.org/techniques/T1008). When contact is lost with the primary command and control server malware may employ dynamic resolution as a means to reestablishing command and control.(Citation: Talos CCleanup 2017)(Citation: FireEye POSHSPY April 2017)(Citation: ESET Sednit 2017 Activity)<br /><br />",
    "technique_references": [
      {
        "source_name": "Talos CCleanup 2017",
        "url": "http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html",
        "description": "Brumaghin, E. et al. (2017, September 18). CCleanup: A Vast Number of Machines at Risk. Retrieved March 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye POSHSPY April 2017",
        "url": "https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html",
        "description": "Dunwoody, M.. (2017, April 3). Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY). Retrieved April 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "ESET Sednit 2017 Activity",
        "url": "https://www.welivesecurity.com/2017/12/21/sednit-update-fancy-bear-spent-year/",
        "description": "ESET. (2017, December 21). Sednit update: How Fancy Bear Spent the Year. Retrieved February 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Data Driven Security DGA",
        "url": "https://datadrivensecurity.info/blog/posts/2014/Oct/dga-part2/",
        "description": "Jacobs, J. (2014, October 2). Building a DGA Classifier: Part 2, Feature Engineering. Retrieved February 18, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b18eae87-b469-4e14-b454-b171b416bc18",
    "platform": "linux|macos|windows",
    "tid": "T1571",
    "technique": "Non-Standard Port",
    "tactic": "command-and-control",
    "datasources": "netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may communicate using a protocol and port paring that are typically not associated. For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.<br /><br />",
    "technique_references": [
      {
        "source_name": "Symantec Elfin Mar 2019",
        "url": "https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage",
        "description": "Security Response attack Investigation Team. (2019, March 27). Elfin: Relentless Espionage Group Targets Multiple Organizations in Saudi Arabia and U.S.. Retrieved April 10, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Fortinet Agent Tesla April 2018",
        "url": "https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html",
        "description": "Zhang, X. (2018, April 05). Analysis of New Agent Tesla Spyware Variant. Retrieved November 5, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--4fe28b27-b13c-453e-a386-c2ef362a573b",
    "platform": "linux|macos|windows",
    "tid": "T1572",
    "technique": "Protocol Tunneling",
    "tactic": "command-and-control",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet. <br /><br />There are various means to encapsulate a protocol within another protocol. For example, adversaries may perform SSH tunneling (also known as SSH port forwarding), which involves forwarding arbitrary data over an encrypted SSH tunnel.(Citation: SSH Tunneling) <br /><br />[Protocol Tunneling](https://attack.mitre.org/techniques/T1572) may also be abused by adversaries during [Dynamic Resolution](https://attack.mitre.org/techniques/T1568). Known as DNS over HTTPS (DoH), queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets.(Citation: BleepingComp Godlua JUL19) <br /><br />Adversaries may also leverage [Protocol Tunneling](https://attack.mitre.org/techniques/T1572) in conjunction with [Proxy](https://attack.mitre.org/techniques/T1090) and/or [Protocol Impersonation](https://attack.mitre.org/techniques/T1001/003) to further conceal C2 communications and infrastructure. <br /><br />",
    "technique_references": [
      {
        "source_name": "SSH Tunneling",
        "url": "https://www.ssh.com/ssh/tunneling",
        "description": "SSH.COM. (n.d.). SSH tunnel. Retrieved March 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "BleepingComp Godlua JUL19",
        "url": "https://www.bleepingcomputer.com/news/security/new-godlua-malware-evades-traffic-monitoring-via-dns-over-https/",
        "description": "Gatlan, S. (2019, July 3). New Godlua Malware Evades Traffic Monitoring via DNS over HTTPS. Retrieved March 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b8902400-e6c5-4ba2-95aa-2d35b442b118",
    "platform": "linux|macos|windows",
    "tid": "T1573",
    "technique": "Encrypted Channel",
    "tactic": "command-and-control",
    "datasources": "malware-reverse-engineering|netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network|ssl-tls-inspection",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1573.001",
      "T1573.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.<br /><br />",
    "technique_references": [
      {
        "source_name": "SANS Decrypting SSL",
        "url": "http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840",
        "description": "Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "SEI SSL Inspection Risks",
        "url": "https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html",
        "description": "Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "University of Birmingham C2",
        "url": "https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf",
        "description": "Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.",
        "external_id": "none"
      }
    ]
  }
]
