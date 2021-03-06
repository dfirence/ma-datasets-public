 [
  {
    "item": "T1003",
    "meta": "OS Credential Dumping",
    "count_techniques": 0,
    "count_subtechniques": 8,
    "count_platforms": 3,
    "count_tactics": 1,
    "count_datasources": 4,
    "count_adversaries": 9,
    "count_malware": 6,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "2%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access",
    "the_subtechniques": "T1003.001|T1003.002|T1003.003|T1003.004|T1003.005|T1003.006|T1003.007|T1003.008",
    "the_platforms": "windows|linux|macos",
    "the_adversaries": "apt28|apt32|apt39|axiom|frankenstein|leviathan|poseidon-group|sowbug|suckfly",
    "the_malware": "carbanak|homefry|onionduke|pinchduke|revenge-rat|trojan.karagany",
    "the_tools": "non",
    "the_datasources": "api-monitoring|powershell-logs|process-command-line-parameters|process-monitoring"
  },
  {
    "item": "T1040",
    "meta": "Network Sniffing",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 3,
    "count_tactics": 2,
    "count_datasources": 4,
    "count_adversaries": 5,
    "count_malware": 3,
    "count_tools": 4,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "0%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access|discovery",
    "the_subtechniques": "non",
    "the_platforms": "linux|macos|windows",
    "the_adversaries": "apt28|apt33|darkvishnya|sandworm-team|stolen-pencil",
    "the_malware": "emotet|messagetap|regin",
    "the_tools": "empire|impacket|poshc2|responder",
    "the_datasources": "host-network-interface|netflow-enclave-netflow|network-device-logs|process-monitoring"
  },
  {
    "item": "T1056",
    "meta": "Input Capture",
    "count_techniques": 0,
    "count_subtechniques": 4,
    "count_platforms": 4,
    "count_tactics": 2,
    "count_datasources": 11,
    "count_adversaries": 0,
    "count_malware": 0,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "1%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "collection|credential-access",
    "the_subtechniques": "T1056.001|T1056.002|T1056.003|T1056.004",
    "the_platforms": "linux|macos|windows|network",
    "the_adversaries": "non",
    "the_malware": "non",
    "the_tools": "non",
    "the_datasources": "api-monitoring|binary-file-metadata|dll-monitoring|kernel-drivers|loaded-dlls|powershell-logs|process-command-line-parameters|process-monitoring|user-interface|windows-event-logs|windows-registry"
  },
  {
    "item": "T1110",
    "meta": "Brute Force",
    "count_techniques": 0,
    "count_subtechniques": 4,
    "count_platforms": 9,
    "count_tactics": 1,
    "count_datasources": 2,
    "count_adversaries": 5,
    "count_malware": 1,
    "count_tools": 2,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "1%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access",
    "the_subtechniques": "T1110.001|T1110.002|T1110.003|T1110.004",
    "the_platforms": "linux|macos|windows|office-365|azure-ad|saas|gcp|aws|azure",
    "the_adversaries": "apt39|darkvishnya|fin5|oilrig|turla",
    "the_malware": "chaos",
    "the_tools": "crackmapexec|poshc2",
    "the_datasources": "authentication-logs|office-365-account-logs"
  },
  {
    "item": "T1111",
    "meta": "Two-Factor Authentication Interception",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 3,
    "count_tactics": 1,
    "count_datasources": 3,
    "count_adversaries": 0,
    "count_malware": 1,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "0%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access",
    "the_subtechniques": "non",
    "the_platforms": "linux|windows|macos",
    "the_adversaries": "non",
    "the_malware": "sykipot",
    "the_tools": "non",
    "the_datasources": "api-monitoring|kernel-drivers|process-monitoring"
  },
  {
    "item": "T1187",
    "meta": "Forced Authentication",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 1,
    "count_tactics": 1,
    "count_datasources": 4,
    "count_adversaries": 2,
    "count_malware": 0,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "0%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access",
    "the_subtechniques": "non",
    "the_platforms": "windows",
    "the_adversaries": "darkhydrus|dragonfly-2.0",
    "the_malware": "non",
    "the_tools": "non",
    "the_datasources": "file-monitoring|network-device-logs|network-protocol-analysis|process-use-of-network"
  },
  {
    "item": "T1212",
    "meta": "Exploitation for Credential Access",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 3,
    "count_tactics": 1,
    "count_datasources": 3,
    "count_adversaries": 0,
    "count_malware": 0,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "0%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access",
    "the_subtechniques": "non",
    "the_platforms": "linux|windows|macos",
    "the_adversaries": "non",
    "the_malware": "non",
    "the_tools": "non",
    "the_datasources": "authentication-logs|process-monitoring|windows-error-reporting"
  },
  {
    "item": "T1528",
    "meta": "Steal Application Access Token",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 3,
    "count_tactics": 1,
    "count_datasources": 2,
    "count_adversaries": 1,
    "count_malware": 0,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "0%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access",
    "the_subtechniques": "non",
    "the_platforms": "saas|office-365|azure-ad",
    "the_adversaries": "apt28",
    "the_malware": "non",
    "the_tools": "non",
    "the_datasources": "azure-activity-logs|oauth-audit-logs"
  },
  {
    "item": "T1539",
    "meta": "Steal Web Session Cookie",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 5,
    "count_tactics": 1,
    "count_datasources": 2,
    "count_adversaries": 0,
    "count_malware": 2,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "0%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access",
    "the_subtechniques": "non",
    "the_platforms": "linux|macos|windows|office-365|saas",
    "the_adversaries": "non",
    "the_malware": "cookieminer|tajmahal",
    "the_tools": "non",
    "the_datasources": "api-monitoring|file-monitoring"
  },
  {
    "item": "T1552",
    "meta": "Unsecured Credentials",
    "count_techniques": 0,
    "count_subtechniques": 6,
    "count_platforms": 9,
    "count_tactics": 1,
    "count_datasources": 8,
    "count_adversaries": 0,
    "count_malware": 1,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "2%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access",
    "the_subtechniques": "T1552.001|T1552.002|T1552.003|T1552.004|T1552.005|T1552.006",
    "the_platforms": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "the_adversaries": "non",
    "the_malware": "astaroth",
    "the_tools": "non",
    "the_datasources": "authentication-logs|aws-cloudtrail-logs|azure-activity-logs|file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs|windows-registry"
  },
  {
    "item": "T1555",
    "meta": "Credentials from Password Stores",
    "count_techniques": 0,
    "count_subtechniques": 3,
    "count_platforms": 3,
    "count_tactics": 1,
    "count_datasources": 5,
    "count_adversaries": 8,
    "count_malware": 14,
    "count_tools": 5,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "1%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access",
    "the_subtechniques": "T1555.001|T1555.002|T1555.003",
    "the_platforms": "linux|macos|windows",
    "the_adversaries": "apt33|apt39|fin6|leafminer|muddywater|oilrig|stealth-falcon|turla",
    "the_malware": "agent-tesla|astaroth|carberp|cosmicduke|lokibot|matroyshka|oldbait|plead|pinchduke|prikormka|proton|rokrat|trickbot|valak",
    "the_tools": "lazagne|mimikatz|powersploit|pupy|quasarrat",
    "the_datasources": "api-monitoring|file-monitoring|powershell-logs|process-monitoring|system-calls"
  },
  {
    "item": "T1556",
    "meta": "Modify Authentication Process",
    "count_techniques": 0,
    "count_subtechniques": 4,
    "count_platforms": 4,
    "count_tactics": 2,
    "count_datasources": 6,
    "count_adversaries": 0,
    "count_malware": 2,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "1%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access|defense-evasion",
    "the_subtechniques": "T1556.001|T1556.002|T1556.003|T1556.004",
    "the_platforms": "windows|linux|macos|network",
    "the_adversaries": "non",
    "the_malware": "ebury|kessel",
    "the_tools": "non",
    "the_datasources": "api-monitoring|authentication-logs|dll-monitoring|file-monitoring|process-monitoring|windows-registry"
  },
  {
    "item": "T1557",
    "meta": "Man-in-the-Middle",
    "count_techniques": 0,
    "count_subtechniques": 2,
    "count_platforms": 3,
    "count_tactics": 2,
    "count_datasources": 3,
    "count_adversaries": 0,
    "count_malware": 0,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "1%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access|collection",
    "the_subtechniques": "T1557.001|T1557.002",
    "the_platforms": "windows|macos|linux",
    "the_adversaries": "non",
    "the_malware": "non",
    "the_tools": "non",
    "the_datasources": "file-monitoring|netflow-enclave-netflow|packet-capture"
  },
  {
    "item": "T1558",
    "meta": "Steal or Forge Kerberos Tickets",
    "count_techniques": 0,
    "count_subtechniques": 4,
    "count_platforms": 1,
    "count_tactics": 1,
    "count_datasources": 2,
    "count_adversaries": 0,
    "count_malware": 0,
    "count_tools": 0,
    "percent_malware": "%",
    "percent_tools": "%",
    "percent_tactics": "%",
    "percent_techniques": "0%",
    "percent_subtechniques": "1%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "credential-access",
    "the_subtechniques": "T1558.001|T1558.002|T1558.003|T1558.004",
    "the_platforms": "windows",
    "the_adversaries": "non",
    "the_malware": "non",
    "the_tools": "non",
    "the_datasources": "authentication-logs|windows-event-logs"
  }
]
