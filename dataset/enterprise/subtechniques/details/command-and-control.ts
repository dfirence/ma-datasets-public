 [
  {
    "id": "attack-pattern--f7c0689c-4dbd-489b-81be-7cb7c7079ade",
    "platform": "linux|macos|windows",
    "tid": "T1001.001",
    "technique": "Junk Data",
    "tactic": "command-and-control",
    "datasources": "network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may add junk data to protocols used for command and control to make detection more difficult. By adding random or meaningless data to the protocols used for command and control, adversaries can prevent trivial methods for decoding, deciphering, or otherwise analyzing the traffic. Examples may include appending/prepending data with junk characters or writing junk characters between significant characters. <br /><br />",
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
    "id": "attack-pattern--eec23884-3fa1-4d8a-ac50-6f104d51e235",
    "platform": "linux|macos|windows",
    "tid": "T1001.002",
    "technique": "Steganography",
    "tactic": "command-and-control",
    "datasources": "network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use steganographic techniques to hide command and control traffic to make detection efforts more difficult. Steganographic techniques can be used to hide data in digital messages that are transferred between systems. This hidden information can be used for command and control of compromised systems. In some cases, the passing of files embedded using steganography, such as image or document files, can be used for command and control. <br /><br />",
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
    "id": "attack-pattern--c325b232-d5bc-4dde-a3ec-71f3db9e8adc",
    "platform": "linux|windows|macos",
    "tid": "T1001.003",
    "technique": "Protocol Impersonation",
    "tactic": "command-and-control",
    "datasources": "network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may impersonate legitimate protocols or web service traffic to disguise command and control activity and thwart analysis efforts. By impersonating legitimate protocols or web services, adversaries can make their command and control traffic blend in with legitimate network traffic.  <br /><br />Adversaries may impersonate a fake SSL/TLS handshake to make it look like subsequent traffic is SSL/TLS encrypted, potentially interfering with some security tooling, or to make the traffic look like it is related with a trusted entity. <br /><br />",
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
    "id": "attack-pattern--df8b2a25-8bdf-4856-953c-a04372b1c161",
    "platform": "linux|macos|windows",
    "tid": "T1071.001",
    "technique": "Web Protocols",
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
    "technique_description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. <br /><br />Protocols such as HTTP and HTTPS that carry web traffic may be very common in environments. HTTP/S packets have many fields and headers in which data can be concealed. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic. <br /><br />",
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
    "id": "attack-pattern--9a60a291-8960-4387-8a4a-2ab5c18bb50b",
    "platform": "linux|macos|windows",
    "tid": "T1071.002",
    "technique": "File Transfer Protocols",
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
    "technique_description": "Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. <br /><br />Protocols such as FTP, FTPS, and TFTP that transfer files may be very common in environments.  Packets produced from these protocols may have many fields and headers in which data can be concealed. Data could also be concealed within the transferred files. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic. <br /><br />",
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
    "id": "attack-pattern--54b4c251-1f0e-4eba-ba6b-dbc7a6f6f06b",
    "platform": "linux|macos|windows",
    "tid": "T1071.003",
    "technique": "Mail Protocols",
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
    "technique_description": "Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. <br /><br />Protocols such as SMTP/S, POP3/S, and IMAP that carry electronic mail may be very common in environments.  Packets produced from these protocols may have many fields and headers in which data can be concealed. Data could also be concealed within the email messages themselves. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic. <br /><br />",
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
    "id": "attack-pattern--1996eef1-ced3-4d7f-bf94-33298cabbf72",
    "platform": "linux|macos|windows",
    "tid": "T1071.004",
    "technique": "DNS",
    "tactic": "command-and-control",
    "datasources": "dns-records|netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. <br /><br />The DNS protocol serves an administrative function in computer networking and thus may be very common in environments. DNS traffic may also be allowed even before network authentication is completed. DNS packets contain many fields and headers in which data can be concealed. Often known as DNS tunneling, adversaries may abuse DNS to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.(Citation: PAN DNS Tunneling)(Citation: Medium DnsTunneling) <br /><br />",
    "technique_references": [
      {
        "source_name": "PAN DNS Tunneling",
        "url": "https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling",
        "description": "Palo Alto Networks. (n.d.). What Is DNS Tunneling?. Retrieved March 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Medium DnsTunneling",
        "url": "https://medium.com/@galolbardes/learn-how-easy-is-to-bypass-firewalls-using-dns-tunneling-and-also-how-to-block-it-3ed652f4a000",
        "description": "Galobardes, R. (2018, October 30). Learn how easy is to bypass firewalls using DNS tunneling (and also how to block it). Retrieved March 15, 2020.",
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
    "id": "attack-pattern--f6dacc85-b37d-458e-b58d-74fc4bbf5755",
    "platform": "linux|macos|windows",
    "tid": "T1090.001",
    "technique": "Internal Proxy",
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
    "technique_description": "Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use internal proxies to manage command and control communications inside a compromised environment, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between infected systems to avoid suspicion. Internal proxy connections may use common peer-to-peer (p2p) networking protocols, such as SMB, to better blend in with the environment.<br /><br />By using a compromised internal system as a proxy, adversaries may conceal the true destination of C2 traffic while reducing the need for numerous connections to external systems.<br /><br />",
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
    "id": "attack-pattern--69b8fd78-40e8-4600-ae4d-662c9d7afdb3",
    "platform": "linux|macos|windows",
    "tid": "T1090.002",
    "technique": "External Proxy",
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
    "technique_description": "Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use these types of proxies to manage command and control communications, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths to avoid suspicion.<br /><br />External connection proxies are used to mask the destination of C2 traffic and are typically implemented with port redirectors. Compromised systems outside of the victim environment may be used for these purposes, as well as purchased infrastructure such as cloud-based resources or virtual private servers. Proxies may be chosen based on the low likelihood that a connection to them from a compromised system would be investigated. Victim systems would communicate directly with the external proxy on the Internet and then the proxy would forward communications to the C2 server.<br /><br />",
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
    "id": "attack-pattern--a782ebe2-daba-42c7-bc82-e8e9d923162d",
    "platform": "linux|macos|windows|network",
    "tid": "T1090.003",
    "technique": "Multi-hop Proxy",
    "tactic": "command-and-control",
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
    "technique_description": "To disguise the source of malicious traffic, adversaries may chain together multiple proxies. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source. A particular variant of this behavior is to use onion routing networks, such as the publicly available TOR network. (Citation: Onion Routing)<br /><br />In the case of network infrastructure, particularly routers, it is possible for an adversary to leverage multiple compromised devices to create a multi-hop proxy chain within the Wide-Area Network (WAN) of the enterprise.  By leveraging [Patch System Image](https://attack.mitre.org/techniques/T1601/001), adversaries can add custom code to the affected network devices that will implement onion routing between those nodes.  This custom onion routing network will transport the encrypted C2 traffic through the compromised population, allowing adversaries to communicate with any device within the onion routing network.  This method is dependent upon the [Network Boundary Bridging](https://attack.mitre.org/techniques/T1599) method in order to allow the adversaries to cross the protected network boundary of the Internet perimeter and into the organization’s WAN. Protocols such as ICMP may be used as a transport.<br /><br />",
    "technique_references": [
      {
        "source_name": "Onion Routing",
        "url": "https://en.wikipedia.org/wiki/Onion_routing",
        "description": "Wikipedia. (n.d.). Onion Routing. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ca9d3402-ada3-484d-876a-d717bd6e05f2",
    "platform": "linux|macos|windows",
    "tid": "T1090.004",
    "technique": "Domain Fronting",
    "tactic": "command-and-control",
    "datasources": "packet-capture|ssl-tls-inspection",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS. (Citation: Fifield Blocking Resistent Communication through domain fronting 2015) Domain fronting involves using different domain names in the SNI field of the TLS header and the Host field of the HTTP header. If both domains are served from the same CDN, then the CDN may route to the address specified in the HTTP header after unwrapping the TLS header. A variation of the the technique, \"domainless\" fronting, utilizes a SNI field that is left blank; this may allow the fronting to work even when the CDN attempts to validate that the SNI and HTTP Host fields match (if the blank SNI fields are ignored).<br /><br />For example, if domain-x and domain-y are customers of the same CDN, it is possible to place domain-x in the TLS header and domain-y in the HTTP header. Traffic will appear to be going to domain-x, however the CDN may route it to domain-y.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/481.html",
        "description": "none",
        "external_id": "CAPEC-481"
      },
      {
        "source_name": "Fifield Blocking Resistent Communication through domain fronting 2015",
        "url": "http://www.icir.org/vern/papers/meek-PETS-2015.pdf",
        "description": "David Fifield, Chang Lan, Rod Hynes, Percy Wegmann, and Vern Paxson. (2015). Blocking-resistant communication through domain fronting. Retrieved November 20, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f7827069-0bf2-4764-af4f-23fae0d181b7",
    "platform": "linux|macos|windows",
    "tid": "T1102.001",
    "technique": "Dead Drop Resolver",
    "tactic": "command-and-control",
    "datasources": "host-network-interface|netflow-enclave-netflow|network-protocol-analysis|packet-capture|ssl-tls-inspection",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach out to and be redirected by these resolvers.<br /><br />Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.<br /><br />Use of a dead drop resolver may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).<br /><br />",
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
    "id": "attack-pattern--be055942-6e63-49d7-9fa1-9cb7d8a8f3f4",
    "platform": "linux|macos|windows",
    "tid": "T1102.002",
    "technique": "Bidirectional Communication",
    "tactic": "command-and-control",
    "datasources": "host-network-interface|netflow-enclave-netflow|network-protocol-analysis|packet-capture|ssl-tls-inspection",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems can then send the output from those commands back over that Web service channel. The return traffic may occur in a variety of ways, depending on the Web service being utilized. For example, the return traffic may take the form of the compromised system posting a comment on a forum, issuing a pull request to development project, updating a document hosted on a Web service, or by sending a Tweet. <br /><br />Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection. <br /><br />",
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
    "id": "attack-pattern--9c99724c-a483-4d60-ad9d-7f004e42e8e8",
    "platform": "linux|macos|windows",
    "tid": "T1102.003",
    "technique": "One-Way Communication",
    "tactic": "command-and-control",
    "datasources": "host-network-interface|netflow-enclave-netflow|network-protocol-analysis|packet-capture|ssl-tls-inspection",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use an existing, legitimate external Web service as a means for sending commands to a compromised system without receiving return output over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems may opt to send the output from those commands back over a different C2 channel, including to another distinct Web service. Alternatively, compromised systems may return no output at all in cases where adversaries want to send instructions to systems and do not want a response.<br /><br />Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.<br /><br />",
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
    "id": "attack-pattern--04fd5427-79c7-44ea-ae13-11b24778ff1c",
    "platform": "linux|macos|windows",
    "tid": "T1132.001",
    "technique": "Standard Encoding",
    "tactic": "command-and-control",
    "datasources": "network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications. Common data encoding schemes include ASCII, Unicode, hexadecimal, Base64, and MIME.(Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some data encoding systems may also result in data compression, such as gzip.<br /><br />",
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
    "id": "attack-pattern--d467bc38-284b-4a00-96ac-125f447799fc",
    "platform": "linux|macos|windows",
    "tid": "T1132.002",
    "technique": "Non-Standard Encoding",
    "tactic": "command-and-control",
    "datasources": "network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may encode data with a non-standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a non-standard data encoding system that diverges from existing protocol specifications. Non-standard data encoding schemes may be based on or related to standard data encoding schemes, such as a modified Base64 encoding for the message body of an HTTP request.(Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) <br /><br />",
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
    "id": "attack-pattern--8868cb5b-d575-4a60-acb2-07d37389a2fd",
    "platform": "linux|macos|windows|network",
    "tid": "T1205.001",
    "technique": "Port Knocking",
    "tactic": "command-and-control",
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
    "technique_description": "Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software.<br /><br />This technique has been observed to both for the dynamic opening of a listening port as well as the initiating of a connection to a listening server on a different system.<br /><br />The observation of the signal packets to trigger the communication can be conducted through different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r 2002), is to use the libpcap libraries to sniff for the packets in question. Another method leverages raw sockets, which enables the malware to use ports that are already open for use by other programs.<br /><br />",
    "technique_references": [
      {
        "source_name": "Hartrell cd00r 2002",
        "url": "https://www.giac.org/paper/gcih/342/handle-cd00r-invisible-backdoor/103631",
        "description": "Hartrell, Greg. (2002, August). Get a handle on cd00r: The invisible backdoor. Retrieved October 13, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--29ba5a15-3b7b-4732-b817-65ea8f6468e6",
    "platform": "linux|macos|windows",
    "tid": "T1568.001",
    "technique": "Fast Flux DNS",
    "tactic": "command-and-control",
    "datasources": "dns-records",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use Fast Flux DNS to hide a command and control channel behind an array of rapidly changing IP addresses linked to a single domain resolution. This technique uses a fully qualified domain name, with multiple IP addresses assigned to it which are swapped with high frequency, using a combination of round robin IP addressing and short Time-To-Live (TTL) for a DNS resource record.(Citation: MehtaFastFluxPt1)(Citation: MehtaFastFluxPt2)(Citation: Fast Flux - Welivesecurity)<br /><br />The simplest, \"single-flux\" method, involves registering and de-registering an addresses as part of the DNS A (address) record list for a single DNS name. These registrations have a five-minute average lifespan, resulting in a constant shuffle of IP address resolution.(Citation: Fast Flux - Welivesecurity)<br /><br />In contrast, the \"double-flux\" method registers and de-registers an address as part of the DNS Name Server record list for the DNS zone, providing additional resilience for the connection. With double-flux additional hosts can act as a proxy to the C2 host, further insulating the true source of the C2 channel.<br /><br />",
    "technique_references": [
      {
        "source_name": "MehtaFastFluxPt1",
        "url": "https://resources.infosecinstitute.com/fast-flux-networks-working-detection-part-1/#gref",
        "description": "Mehta, L. (2014, December 17). Fast Flux Networks Working and Detection, Part 1. Retrieved March 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "MehtaFastFluxPt2",
        "url": "https://resources.infosecinstitute.com/fast-flux-networks-working-detection-part-2/#gref",
        "description": "Mehta, L. (2014, December 23). Fast Flux Networks Working and Detection, Part 2. Retrieved March 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Fast Flux - Welivesecurity",
        "url": "https://www.welivesecurity.com/2017/01/12/fast-flux-networks-work/",
        "description": "Albors, Josep. (2017, January 12). Fast Flux networks: What are they and how do they work?. Retrieved March 11, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--118f61a5-eb3e-4fb6-931f-2096647f4ecd",
    "platform": "linux|macos|windows",
    "tid": "T1568.002",
    "technique": "Domain Generation Algorithms",
    "tactic": "command-and-control",
    "datasources": "dns-records|netflow-enclave-netflow|network-device-logs|packet-capture|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination domain for command and control traffic rather than relying on a list of static IP addresses or domains. This has the advantage of making it much harder for defenders block, track, or take over the command and control channel, as there potentially could be thousands of domains that malware can check for instructions.(Citation: Cybereason Dissecting DGAs)(Citation: Cisco Umbrella DGA)(Citation: Unit 42 DGA Feb 2019)<br /><br />DGAs can take the form of apparently random or “gibberish” strings (ex: istgmxdejdnxuyla.ru) when they construct domain names by generating each letter. Alternatively, some DGAs employ whole words as the unit by concatenating words together instead of letters (ex: cityjulydish.net). Many DGAs are time-based, generating a different domain for each time period (hourly, daily, monthly, etc). Others incorporate a seed value as well to make predicting future domains more difficult for defenders.(Citation: Cybereason Dissecting DGAs)(Citation: Cisco Umbrella DGA)(Citation: Talos CCleanup 2017)(Citation: Akamai DGA Mitigation)<br /><br />Adversaries may use DGAs for the purpose of [Fallback Channels](https://attack.mitre.org/techniques/T1008). When contact is lost with the primary command and control server malware may employ a DGA as a means to reestablishing command and control.(Citation: Talos CCleanup 2017)(Citation: FireEye POSHSPY April 2017)(Citation: ESET Sednit 2017 Activity)<br /><br />",
    "technique_references": [
      {
        "source_name": "Cybereason Dissecting DGAs",
        "url": "http://go.cybereason.com/rs/996-YZT-709/images/Cybereason-Lab-Analysis-Dissecting-DGAs-Eight-Real-World-DGA-Variants.pdf",
        "description": "Sternfeld, U. (2016). Dissecting Domain Generation Algorithms: Eight Real World DGA Variants. Retrieved February 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Umbrella DGA",
        "url": "https://umbrella.cisco.com/blog/2016/10/10/domain-generation-algorithms-effective/",
        "description": "Scarfo, A. (2016, October 10). Domain Generation Algorithms – Why so effective?. Retrieved February 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Unit 42 DGA Feb 2019",
        "url": "https://unit42.paloaltonetworks.com/threat-brief-understanding-domain-generation-algorithms-dga/",
        "description": "Unit 42. (2019, February 7). Threat Brief: Understanding Domain Generation Algorithms (DGA). Retrieved February 19, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Talos CCleanup 2017",
        "url": "http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html",
        "description": "Brumaghin, E. et al. (2017, September 18). CCleanup: A Vast Number of Machines at Risk. Retrieved March 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Akamai DGA Mitigation",
        "url": "https://blogs.akamai.com/2018/01/a-death-match-of-domain-generation-algorithms.html",
        "description": "Liu, H. and Yuzifovich, Y. (2018, January 9). A Death Match of Domain Generation Algorithms. Retrieved February 18, 2019.",
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
      },
      {
        "source_name": "Pace University Detecting DGA May 2017",
        "url": "http://csis.pace.edu/~ctappert/srd2017/2017PDF/d4.pdf",
        "description": "Chen, L., Wang, T.. (2017, May 5). Detecting Algorithmically Generated Domains Using Data Visualization and N-Grams Methods . Retrieved April 26, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame Predicting DGA",
        "url": "https://arxiv.org/pdf/1611.00791.pdf",
        "description": "Ahuja, A., Anderson, H., Grant, D., Woodbridge, J.. (2016, November 2). Predicting Domain Generation Algorithms with Long Short-Term Memory Networks. Retrieved April 26, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--83a766f8-1501-4b3a-a2de-2e2849e8dfc1",
    "platform": "linux|macos|windows",
    "tid": "T1568.003",
    "technique": "DNS Calculation",
    "tactic": "command-and-control",
    "datasources": "dns-records",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may perform calculations on addresses returned in DNS results to determine which port and IP address to use for command and control, rather than relying on a predetermined port number or the actual returned IP address. A IP and/or port number calculation can be used to bypass egress filtering on a C2 channel.(Citation: Meyers Numbered Panda)<br /><br />One implementation of [DNS Calculation](https://attack.mitre.org/techniques/T1568/003) is to take the first three octets of an IP address in a DNS response and use those values to calculate the port for command and control traffic.(Citation: Meyers Numbered Panda)(Citation: Moran 2014)(Citation: Rapid7G20Espionage)<br /><br />",
    "technique_references": [
      {
        "source_name": "Meyers Numbered Panda",
        "url": "http://www.crowdstrike.com/blog/whois-numbered-panda/",
        "description": "Meyers, A. (2013, March 29). Whois Numbered Panda. Retrieved January 14, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Moran 2014",
        "url": "https://www.fireeye.com/blog/threat-research/2014/09/darwins-favorite-apt-group-2.html",
        "description": "Moran, N., Oppenheim, M., Engle, S., & Wartell, R.. (2014, September 3). Darwin’s Favorite APT Group &#91;Blog&#93;. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Rapid7G20Espionage",
        "url": "https://blog.rapid7.com/2013/08/26/upcoming-g20-summit-fuels-espionage-operations/",
        "description": "Rapid7. (2013, August 26). Upcoming G20 Summit Fuels Espionage Operations. Retrieved March 6, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--24bfaeba-cb0d-4525-b3dc-507c77ecec41",
    "platform": "linux|windows|macos",
    "tid": "T1573.001",
    "technique": "Symmetric Cryptography",
    "tactic": "command-and-control",
    "datasources": "malware-reverse-engineering|netflow-enclave-netflow|packet-capture|process-monitoring|process-use-of-network|ssl-tls-inspection",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption. Common symmetric encryption algorithms include AES, DES, 3DES, Blowfish, and RC4.<br /><br />",
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
    "id": "attack-pattern--bf176076-b789-408e-8cba-7275e81c0ada",
    "platform": "linux|macos|windows",
    "tid": "T1573.002",
    "technique": "Asymmetric Cryptography",
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
    "technique_description": "Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Asymmetric cryptography, also known as public key cryptography, uses a keypair per party: one public that can be freely distributed, and one private. Due to how the keys are generated, the sender encrypts data with the receiver’s public key and the receiver decrypts the data with their private key. This ensures that only the intended recipient can read the encrypted data. Common public key encryption algorithms include RSA and ElGamal.<br /><br />For efficiency, may protocols (including SSL/TLS) use symmetric cryptography once a connection is established, but use asymmetric cryptography to establish or transmit a key. As such, these protocols are classified as [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002).<br /><br />",
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
