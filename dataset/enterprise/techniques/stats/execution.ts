 [
  {
    "item": "T1047",
    "meta": "Windows Management Instrumentation",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 1,
    "count_tactics": 1,
    "count_datasources": 4,
    "count_adversaries": 18,
    "count_malware": 34,
    "count_tools": 6,
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
    "the_tactics": "execution",
    "the_subtechniques": "non",
    "the_platforms": "windows",
    "the_adversaries": "apt29|apt32|apt41|blue-mockingbird|chimera|deep-panda|fin6|fin8|frankenstein|lazarus-group|leviathan|muddywater|oilrig|soft-cell|stealth-falcon|threat-group-3390|wizard-spider|menupass",
    "the_malware": "astaroth|blackenergy|dustysky|emotet|evilbunny|felixroot|flawedammyy|gravityrat|halfbaked|hoplight|icedid|komprogo|kazuar|maze|micropsia|mosquito|netwalker|notpetya|octopus|olympic-destroyer|oopsie|powerstats|powruner|ratankba|revil|remexi|roguerobin|stonedrill|ursnif|valak|wannacry|zebrocy|jrat|cobalt-strike",
    "the_tools": "crackmapexec|empire|impacket|koadic|poshc2|powersploit",
    "the_datasources": "authentication-logs|netflow-enclave-netflow|process-command-line-parameters|process-monitoring"
  },
  {
    "item": "T1053",
    "meta": "Scheduled Task/Job",
    "count_techniques": 0,
    "count_subtechniques": 6,
    "count_platforms": 3,
    "count_tactics": 3,
    "count_datasources": 4,
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
    "the_tactics": "execution|persistence|privilege-escalation",
    "the_subtechniques": "T1053.001|T1053.002|T1053.003|T1053.004|T1053.005|T1053.006",
    "the_platforms": "windows|linux|macos",
    "the_adversaries": "non",
    "the_malware": "remsec",
    "the_tools": "non",
    "the_datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs"
  },
  {
    "item": "T1059",
    "meta": "Command and Scripting Interpreter",
    "count_techniques": 0,
    "count_subtechniques": 8,
    "count_platforms": 4,
    "count_tactics": 1,
    "count_datasources": 4,
    "count_adversaries": 12,
    "count_malware": 10,
    "count_tools": 2,
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
    "the_tactics": "execution",
    "the_subtechniques": "T1059.001|T1059.002|T1059.003|T1059.004|T1059.005|T1059.006|T1059.007|T1059.008",
    "the_platforms": "linux|macos|windows|network",
    "the_adversaries": "apt19|apt32|apt39|dragonfly-2.0|fin5|fin6|fin7|ke3chang|molerats|oilrig|stealth-falcon|whitefly",
    "the_malware": "bonadan|chopstick|darkcomet|get2|kessel|matroyshka|speakup|winerack|zeus-panda|gh0st-rat",
    "the_tools": "empire|imminent-monitor",
    "the_datasources": "powershell-logs|process-command-line-parameters|process-monitoring|windows-event-logs"
  },
  {
    "item": "T1072",
    "meta": "Software Deployment Tools",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 3,
    "count_tactics": 2,
    "count_datasources": 7,
    "count_adversaries": 3,
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
    "the_tactics": "execution|lateral-movement",
    "the_subtechniques": "non",
    "the_platforms": "linux|macos|windows",
    "the_adversaries": "apt32|silence|threat-group-1314",
    "the_malware": "wiper",
    "the_tools": "non",
    "the_datasources": "authentication-logs|binary-file-metadata|file-monitoring|process-monitoring|process-use-of-network|third-party-application-logs|windows-registry"
  },
  {
    "item": "T1106",
    "meta": "Native API",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 3,
    "count_tactics": 1,
    "count_datasources": 4,
    "count_adversaries": 8,
    "count_malware": 47,
    "count_tools": 3,
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
    "the_tactics": "execution",
    "the_subtechniques": "non",
    "the_platforms": "windows|macos|linux",
    "the_adversaries": "apt37|chimera|gamaredon-group|gorgon-group|sharpshooter|silence|tropic-trooper|turla",
    "the_malware": "advstoreshell|aria-body|attor|badnews|bbk|backconfig|bankshot|carberp|comrat|denis|fatduke|goldenspy|goopy|hawkball|hancitor|hotcroissant|hyperbro|icedid|innaputrat|invisimole|lightneuron|maze|metamorfo|mosquito|netwalker|pillowmint|pipemon|plugx|polyglotduke|pony|rdfsniffer|revil|rtm|ramsay|rising-sun|ryuk|shimrat|synack|trickbot|ursnif|volgmer|windtail|xagentosx|build_downer|gh0st-rat|njrat|cobalt-strike",
    "the_tools": "empire|imminent-monitor|shimratreporter",
    "the_datasources": "api-monitoring|loaded-dlls|process-monitoring|system-calls"
  },
  {
    "item": "T1129",
    "meta": "Shared Modules",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 1,
    "count_tactics": 1,
    "count_datasources": 4,
    "count_adversaries": 0,
    "count_malware": 9,
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
    "the_tactics": "execution",
    "the_subtechniques": "non",
    "the_platforms": "windows",
    "the_adversaries": "non",
    "the_malware": "astaroth|attor|boostwrite|hydraq|metamorfo|punchbuggy|pipemon|tajmahal|gh0st-rat",
    "the_tools": "non",
    "the_datasources": "api-monitoring|dll-monitoring|file-monitoring|process-monitoring"
  },
  {
    "item": "T1203",
    "meta": "Exploitation for Client Execution",
    "count_techniques": 0,
    "count_subtechniques": 0,
    "count_platforms": 3,
    "count_tactics": 1,
    "count_datasources": 3,
    "count_adversaries": 23,
    "count_malware": 8,
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
    "the_tactics": "execution",
    "the_subtechniques": "non",
    "the_platforms": "linux|windows|macos",
    "the_adversaries": "apt12|apt28|apt29|apt32|apt33|apt37|apt41|bronze-butler|blacktech|cobalt-group|elderwood|frankenstein|inception|lazarus-group|leviathan|muddywater|patchwork|sandworm-team|ta459|the-white-company|threat-group-3390|tropic-trooper|admin@338",
    "the_malware": "bankshot|dealerschoice|evilbunny|hawkball|invisimole|ramsay|speakup|xbash",
    "the_tools": "non",
    "the_datasources": "anti-virus|process-monitoring|system-calls"
  },
  {
    "item": "T1204",
    "meta": "User Execution",
    "count_techniques": 0,
    "count_subtechniques": 2,
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
    "percent_subtechniques": "1%",
    "from_total_tactics": 0,
    "from_total_techniques": 205,
    "from_total_subtechniques": 474,
    "from_total_malware": 0,
    "from_total_tools": 0,
    "is_legacy_matrix": false,
    "the_tactics": "execution",
    "the_subtechniques": "T1204.001|T1204.002",
    "the_platforms": "linux|windows|macos",
    "the_adversaries": "non",
    "the_malware": "non",
    "the_tools": "non",
    "the_datasources": "anti-virus|process-command-line-parameters|process-monitoring"
  },
  {
    "item": "T1559",
    "meta": "Inter-Process Communication",
    "count_techniques": 0,
    "count_subtechniques": 2,
    "count_platforms": 1,
    "count_tactics": 1,
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
    "the_tactics": "execution",
    "the_subtechniques": "T1559.001|T1559.002",
    "the_platforms": "windows",
    "the_adversaries": "non",
    "the_malware": "non",
    "the_tools": "non",
    "the_datasources": "dll-monitoring|file-monitoring|process-monitoring"
  },
  {
    "item": "T1569",
    "meta": "System Services",
    "count_techniques": 0,
    "count_subtechniques": 2,
    "count_platforms": 2,
    "count_tactics": 1,
    "count_datasources": 4,
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
    "the_tactics": "execution",
    "the_subtechniques": "T1569.001|T1569.002",
    "the_platforms": "windows|macos",
    "the_adversaries": "non",
    "the_malware": "non",
    "the_tools": "non",
    "the_datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-registry"
  }
]
