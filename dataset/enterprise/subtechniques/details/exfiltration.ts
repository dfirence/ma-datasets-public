 [
  {
    "id": "attack-pattern--613d08bc-e8f4-4791-80b0-c8b974340dfd",
    "platform": "linux|macos|windows",
    "tid": "T1011.001",
    "technique": "Exfiltration Over Bluetooth",
    "tactic": "exfiltration",
    "datasources": "process-monitoring|user-interface",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to exfiltrate data over Bluetooth rather than the command and control channel. If the command and control network is a wired Internet connection, an attacker may opt to exfiltrate data using a Bluetooth communication channel.<br /><br />Adversaries may choose to do this if they have sufficient access and proximity. Bluetooth connections might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--7c46b364-8496-4234-8a56-f7e6727e21e1",
    "platform": "network",
    "tid": "T1020.001",
    "technique": "Traffic Duplication",
    "tactic": "exfiltration",
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
    "technique_description": "Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised network infrastructure.  Traffic mirroring is a native feature for some network devices and used for network analysis and may be configured to duplicate traffic and forward to one or more destinations for analysis by a network analyzer or other monitoring device. (Citation: Cisco Traffic Mirroring) (Citation: Juniper Traffic Mirroring)<br /><br />Adversaries may abuse traffic mirroring to mirror or redirect network traffic through other network infrastructure they control. Malicious modifications to network devices to enable traffic redirection may be possible through [ROMMONkit](https://attack.mitre.org/techniques/T1542/004) or [Patch System Image](https://attack.mitre.org/techniques/T1601/001).(Citation: US-CERT-TA18-106A)(Citation: Cisco Blog Legacy Device Attacks) Adversaries may use traffic duplication in conjunction with [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Input Capture](https://attack.mitre.org/techniques/T1056), or [Man-in-the-Middle](https://attack.mitre.org/techniques/T1557) depending on the goals and objectives of the adversary.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/117.html",
        "description": "none",
        "external_id": "CAPEC-117"
      },
      {
        "source_name": "Cisco Traffic Mirroring",
        "url": "https://www.cisco.com/c/en/us/td/docs/routers/crs/software/crs_r5-1/interfaces/configuration/guide/hc51xcrsbook/hc51span.html",
        "description": "Cisco. (n.d.). Cisco IOS XR Interface and Hardware Component Configuration Guide for the Cisco CRS Router, Release 5.1.x. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Juniper Traffic Mirroring",
        "url": "https://www.juniper.net/documentation/en_US/junos/topics/concept/port-mirroring-ex-series.html",
        "description": "Juniper. (n.d.). Understanding Port Mirroring on EX2200, EX3200, EX3300, EX4200, EX4500, EX4550, EX6200, and EX8200 Series Switches. Retrieved October 19, 2020.",
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
      }
    ]
  },
  {
    "id": "attack-pattern--79a4052e-1a89-4b09-aea6-51f1d11fe19c",
    "platform": "linux|macos|windows",
    "tid": "T1048.001",
    "technique": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
    "tactic": "exfiltration",
    "datasources": "malware-reverse-engineering|netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. <br /><br />Symmetric encryption algorithms are those that use shared or the same keys/secrets on each end of the channel. This requires an exchange or pre-arranged agreement/possession of the value used to encrypt and decrypt data. <br /><br />Network protocols that use asymmetric encryption often utilize symmetric encryption once keys are exchanged, but adversaries may opt to manually share keys and implement symmetric cryptographic algorithms (ex: RC4, AES) vice using mechanisms that are baked into a protocol. This may result in multiple layers of encryption (in protocols that are natively encrypted such as HTTPS) or encryption in protocols that not typically encrypted (such as HTTP or FTP). <br /><br />",
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
    "id": "attack-pattern--8e350c1d-ac79-4b5c-bd4e-7476d7e84ec5",
    "platform": "linux|macos|windows",
    "tid": "T1048.002",
    "technique": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. <br /><br />Asymmetric encryption algorithms are those that use different keys on each end of the channel. Also known as public-key cryptography, this requires pairs of cryptographic keys that can encrypt/decrypt data from the corresponding key. Each end of the communication channels requires a private key (only in the procession of that entity) and the public key of the other entity. The public keys of each entity are exchanged before encrypted communications begin. <br /><br />Network protocols that use asymmetric encryption (such as HTTPS/TLS/SSL) often utilize symmetric encryption once keys are exchanged. Adversaries may opt to use these encrypted mechanisms that are baked into a protocol. <br /><br />",
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
    "id": "attack-pattern--fb8d023d-45be-47e9-bc51-f56bcae6435b",
    "platform": "linux|macos|windows",
    "tid": "T1048.003",
    "technique": "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. <br /><br />Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted (such as HTTP, FTP, or DNS). This may include custom or publicly available encoding/compression algorithms (such as base64) as well as embedding data within protocol headers and fields. <br /><br />",
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
    "id": "attack-pattern--a3e1e6c5-9c74-4fc0-a16c-a9d228c17829",
    "platform": "linux|macos|windows",
    "tid": "T1052.001",
    "technique": "Exfiltration over USB",
    "tactic": "exfiltration",
    "datasources": "data-loss-prevention|file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--86a96bf6-cf8b-411c-aaeb-8959944d64f7",
    "platform": "linux|macos|windows",
    "tid": "T1567.001",
    "technique": "Exfiltration to Code Repository",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network|ssl-tls-inspection",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: https://api.github.com). Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection.<br /><br />Exfiltration to a code repository can also provide a significant amount of cover to the adversary if it is a popular service already used by hosts within the network. <br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--bf1b6176-597c-4600-bfcd-ac989670f96b",
    "platform": "linux|macos|windows",
    "tid": "T1567.002",
    "technique": "Exfiltration to Cloud Storage",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network|ssl-tls-inspection",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet.<br /><br />Examples of cloud storage services include Dropbox and Google Docs. Exfiltration to these cloud storage services can provide a significant amount of cover to the adversary if hosts within the network are already communicating with the service. <br /><br />",
    "technique_references": []
  }
]
