export const EXFILTRATION_DETAILS = [
  {
    "id": "attack-pattern--51ea26b1-ff1e-4faa-b1a0-1114cd298c87",
    "platform": "linux|macos|windows",
    "tid": "T1011",
    "technique": "Exfiltration Over Other Network Medium",
    "tactic": "exfiltration",
    "datasources": "process-monitoring|user-interface",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1011.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.<br /><br />Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--774a3188-6ba9-4dc4-879d-d54ee48a5ce9",
    "platform": "linux|macos|windows|network",
    "tid": "T1020",
    "technique": "Automated Exfiltration",
    "tactic": "exfiltration",
    "datasources": "file-monitoring|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1020.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection. <br /><br />When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--4eeaf8a9-c86b-4954-a663-9555fb406466",
    "platform": "linux|macos|windows",
    "tid": "T1029",
    "technique": "Scheduled Transfer",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.<br /><br />When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) or [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--c3888c54-775d-4b2f-b759-75a2ececcbfd",
    "platform": "linux|macos|windows",
    "tid": "T1030",
    "technique": "Data Transfer Size Limits",
    "tactic": "exfiltration",
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
    "technique_description": "An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.<br /><br />",
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
    "id": "attack-pattern--92d7da27-2d91-488e-a00c-059dc162766d",
    "platform": "linux|macos|windows",
    "tid": "T1041",
    "technique": "Exfiltration Over C2 Channel",
    "tactic": "exfiltration",
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
    "technique_description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.<br /><br />",
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
    "id": "attack-pattern--a19e86f8-1c0a-4fea-8407-23b73d615776",
    "platform": "linux|macos|windows",
    "tid": "T1048",
    "technique": "Exfiltration Over Alternative Protocol",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1048.001",
      "T1048.002",
      "T1048.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.  <br /><br />Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Different protocol channels could also include Web services such as cloud storage. Adversaries may also opt to encrypt and/or obfuscate these alternate channels. <br /><br />[Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048) can be done using various common operating system utilities such as [Net](https://attack.mitre.org/software/S0039)/SMB or FTP.(Citation: Palo Alto OilRig Oct 2016) <br /><br />",
    "technique_references": [
      {
        "source_name": "Palo Alto OilRig Oct 2016",
        "url": "http://researchcenter.paloaltonetworks.com/2016/10/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/",
        "description": "Grunzweig, J. and Falcone, R.. (2016, October 4). OilRig Malware Campaign Updates Toolset and Expands Targets. Retrieved May 3, 2017.",
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
    "id": "attack-pattern--e6415f09-df0e-48de-9aba-928c902b7549",
    "platform": "linux|macos|windows",
    "tid": "T1052",
    "technique": "Exfiltration Over Physical Medium",
    "tactic": "exfiltration",
    "datasources": "data-loss-prevention|file-monitoring|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1052.001"
    ],
    "count_subtechniques": 1,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--d4bdbdea-eaec-4071-b4f9-5105e12ea4b6",
    "platform": "azure|aws|gcp",
    "tid": "T1537",
    "technique": "Transfer Data to Cloud Account",
    "tactic": "exfiltration",
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
    "technique_description": "Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control on the same service to avoid typical file transfers/downloads and network-based exfiltration detection.<br /><br />A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider. Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces.<br /><br />Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts.(Citation: DOJ GRU Indictment Jul 2018) <br /><br />",
    "technique_references": [
      {
        "source_name": "DOJ GRU Indictment Jul 2018",
        "url": "https://www.justice.gov/file/1080281/download",
        "description": "Mueller, R. (2018, July 13). Indictment - United States of America vs. VIKTOR BORISOVICH NETYKSHO, et al. Retrieved September 13, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--40597f16-0963-4249-bf4c-ac93b7fb9807",
    "platform": "linux|macos|windows",
    "tid": "T1567",
    "technique": "Exfiltration Over Web Service",
    "tactic": "exfiltration",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture|process-monitoring|process-use-of-network|ssl-tls-inspection",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1567.001",
      "T1567.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.<br /><br />Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection.<br /><br />",
    "technique_references": []
  }
]
