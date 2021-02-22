export const RESOURCE_DEVELOPMENT_DETAILS = [
  {
    "id": "attack-pattern--0458aab9-ad42-4eac-9e22-706a95bafee2",
    "platform": "pre",
    "tid": "T1583",
    "technique": "Acquire Infrastructure",
    "tactic": "resource-development",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1583.001",
      "T1583.002",
      "T1583.003",
      "T1583.004",
      "T1583.005",
      "T1583.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may buy, lease, or rent infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations. Infrastructure solutions include physical or cloud servers, domains, and third-party web services.(Citation: TrendmicroHideoutsLease) Additionally, botnets are available for rent or purchase.<br /><br />Use of these infrastructure solutions allows an adversary to stage, launch, and execute an operation. Solutions may help adversary operations blend in with traffic that is seen as normal, such as contact to third-party web services. Depending on the implementation, adversaries may use infrastructure that makes it difficult to physically tie back to them as well as utilize infrastructure that can be rapidly provisioned, modified, and shut down.<br /><br />",
    "technique_references": [
      {
        "source_name": "TrendmicroHideoutsLease",
        "url": "https://documents.trendmicro.com/assets/wp/wp-criminal-hideouts-for-lease.pdf",
        "description": "Max Goncharov. (2015, July 15). Criminal Hideouts for Lease: Bulletproof Hosting Services. Retrieved March 6, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7e3beebd-8bfe-4e7b-a892-e44ab06a75f9",
    "platform": "pre",
    "tid": "T1584",
    "technique": "Compromise Infrastructure",
    "tactic": "resource-development",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1584.001",
      "T1584.002",
      "T1584.003",
      "T1584.004",
      "T1584.005",
      "T1584.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, and third-party web services. Instead of buying, leasing, or renting infrastructure an adversary may compromise infrastructure and use it during other phases of the adversary lifecycle.(Citation: Mandiant APT1)(Citation: ICANNDomainNameHijacking)(Citation: Talos DNSpionage Nov 2018)(Citation: FireEye EPS Awakens Part 2) Additionally, adversaries may compromise numerous machines to form a botnet they can leverage.<br /><br />Use of compromised infrastructure allows an adversary to stage, launch, and execute an operation. Compromised infrastructure can help adversary operations blend in with traffic that is seen as normal, such as contact with high reputation or trusted sites. By using compromised infrastructure, adversaries may make it difficult to tie their actions back to them. Prior to targeting, adversaries may compromise the infrastructure of other adversaries.(Citation: NSA NCSC Turla OilRig)<br /><br />",
    "technique_references": [
      {
        "source_name": "Mandiant APT1",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf",
        "description": "Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "ICANNDomainNameHijacking",
        "url": "https://www.icann.org/groups/ssac/documents/sac-007-en",
        "description": "ICANN Security and Stability Advisory Committee. (2005, July 12). Domain Name Hijacking: Incidents, Threats, Risks and Remediation. Retrieved March 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Talos DNSpionage Nov 2018",
        "url": "https://blog.talosintelligence.com/2018/11/dnspionage-campaign-targets-middle-east.html",
        "description": "Mercer, W., Rascagneres, P. (2018, November 27). DNSpionage Campaign Targets Middle East. Retrieved October 9, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye EPS Awakens Part 2",
        "url": "https://www.fireeye.com/blog/threat-research/2015/12/the-eps-awakens-part-two.html",
        "description": "Winters, R.. (2015, December 20). The EPS Awakens - Part 2. Retrieved January 22, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "NSA NCSC Turla OilRig",
        "url": "https://media.defense.gov/2019/Oct/18/2002197242/-1/-1/0/NSA_CSA_Turla_20191021%20ver%204%20-%20nsa.gov.pdf",
        "description": "NSA/NCSC. (2019, October 21). Cybersecurity Advisory: Turla Group Exploits Iranian APT To Expand Coverage Of Victims. Retrieved October 16, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cdfc5f0a-9bb9-4352-b896-553cfa2d8fd8",
    "platform": "pre",
    "tid": "T1585",
    "technique": "Establish Accounts",
    "tactic": "resource-development",
    "datasources": "social-media-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1585.001",
      "T1585.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. This development could be applied to social media, website, or other publicly available information that could be referenced and scrutinized for legitimacy over the course of an operation using that persona or identity.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage)<br /><br />For operations incorporating social engineering, the utilization of an online persona may be important. These personas may be fictitious or impersonate real people. The persona may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, Google, etc.). Establishing a persona may require development of additional documentation to make them seem real. This could include filling out profile information, developing social networks, or incorporating photos.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage)<br /><br />Establishing accounts can also include the creation of accounts with email providers, which may be directly leveraged for [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566).(Citation: Mandiant APT1)<br /><br />",
    "technique_references": [
      {
        "source_name": "NEWSCASTER2014",
        "url": "https://www.securityweek.com/iranian-hackers-targeted-us-officials-elaborate-social-media-attack-operation",
        "description": "Lennon, M. (2014, May 29). Iranian Hackers Targeted US Officials in Elaborate Social Media Attack Operation. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "BlackHatRobinSage",
        "url": "http://media.blackhat.com/bh-us-10/whitepapers/Ryan/BlackHat-USA-2010-Ryan-Getting-In-Bed-With-Robin-Sage-v1.0.pdf",
        "description": "Ryan, T. (2010). “Getting In Bed with Robin Sage.”. Retrieved March 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Mandiant APT1",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf",
        "description": "Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--81033c3b-16a4-46e4-8fed-9b030dd03c4a",
    "platform": "pre",
    "tid": "T1586",
    "technique": "Compromise Accounts",
    "tactic": "resource-development",
    "datasources": "social-media-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1586.001",
      "T1586.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts (i.e. [Establish Accounts](https://attack.mitre.org/techniques/T1585)), adversaries may compromise existing accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. <br /><br />A variety of methods exist for compromising accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, or by brute forcing credentials (ex: password reuse from breach credential dumps).(Citation: AnonHBGary) Prior to compromising accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation.<br /><br />Personas may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, Google, etc.). Compromised accounts may require additional development, this could include filling out or modifying profile information, further developing social networks, or incorporating photos.<br /><br />Adversaries may directly leverage compromised email accounts for [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566).<br /><br />",
    "technique_references": [
      {
        "source_name": "AnonHBGary",
        "url": "https://arstechnica.com/tech-policy/2011/02/anonymous-speaks-the-inside-story-of-the-hbgary-hack/",
        "description": "Bright, P. (2011, February 15). Anonymous speaks: the inside story of the HBGary hack. Retrieved March 9, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--edadea33-549c-4ed1-9783-8f5a5853cbdf",
    "platform": "pre",
    "tid": "T1587",
    "technique": "Develop Capabilities",
    "tactic": "resource-development",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1587.001",
      "T1587.002",
      "T1587.003",
      "T1587.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may build capabilities that can be used during targeting. Rather than purchasing, freely downloading, or stealing capabilities, adversaries may develop their own capabilities in-house. This is the process of identifying development requirements and building solutions such as malware, exploits, and self-signed certificates. Adversaries may develop capabilities to support their operations throughout numerous phases of the adversary lifecycle.(Citation: Mandiant APT1)(Citation: Kaspersky Sofacy)(Citation: Bitdefender StrongPity June 2020)(Citation: Talos Promethium June 2020)<br /><br />As with legitimate development efforts, different skill sets may be required for developing capabilities. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's development capabilities, provided the adversary plays a role in shaping requirements and maintains a degree of exclusivity to the capability.<br /><br />",
    "technique_references": [
      {
        "source_name": "Mandiant APT1",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf",
        "description": "Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Kaspersky Sofacy",
        "url": "https://securelist.com/sofacy-apt-hits-high-profile-targets-with-updated-toolset/72924/",
        "description": "Kaspersky Lab's Global Research and Analysis Team. (2015, December 4). Sofacy APT hits high profile targets with updated toolset. Retrieved December 10, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "Bitdefender StrongPity June 2020",
        "url": "https://www.bitdefender.com/files/News/CaseStudies/study/353/Bitdefender-Whitepaper-StrongPity-APT.pdf",
        "description": "Tudorica, R. et al. (2020, June 30). StrongPity APT - Revealing Trojanized Tools, Working Hours and Infrastructure. Retrieved July 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Talos Promethium June 2020",
        "url": "https://blog.talosintelligence.com/2020/06/promethium-extends-with-strongpity3.html",
        "description": "Mercer, W. et al. (2020, June 29). PROMETHIUM extends global reach with StrongPity3 APT. Retrieved July 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ce0687a0-e692-4b77-964a-0784a8e54ff1",
    "platform": "pre",
    "tid": "T1588",
    "technique": "Obtain Capabilities",
    "tactic": "resource-development",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1588.001",
      "T1588.002",
      "T1588.003",
      "T1588.004",
      "T1588.005",
      "T1588.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them. Activities may include the acquisition of malware, software (including licenses), exploits, certificates, and information relating to vulnerabilities. Adversaries may obtain capabilities to support their operations throughout numerous phases of the adversary lifecycle.<br /><br />In addition to downloading free malware, software, and exploits from the internet, adversaries may purchase these capabilities from third-party entities. Third-party entities can include technology companies that specialize in malware and exploits, criminal marketplaces, or from individuals.(Citation: NationsBuying)(Citation: PegasusCitizenLab)<br /><br />In addition to purchasing capabilities, adversaries may steal capabilities from third-party entities (including other adversaries). This can include stealing software licenses, malware, SSL/TLS and code-signing certificates, or raiding closed databases of vulnerabilities or exploits.(Citation: DiginotarCompromise)<br /><br />",
    "technique_references": [
      {
        "source_name": "NationsBuying",
        "url": "https://www.nytimes.com/2013/07/14/world/europe/nations-buying-as-hackers-sell-computer-flaws.html",
        "description": "Nicole Perlroth and David E. Sanger. (2013, July 12). Nations Buying as Hackers Sell Flaws in Computer Code. Retrieved March 9, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "PegasusCitizenLab",
        "url": "https://citizenlab.ca/2016/08/million-dollar-dissident-iphone-zero-day-nso-group-uae/",
        "description": "Bill Marczak and John Scott-Railton. (2016, August 24). The Million Dollar Dissident: NSO Group’s iPhone Zero-Days used against a UAE Human Rights Defender. Retrieved December 12, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "DiginotarCompromise",
        "url": "https://threatpost.com/final-report-diginotar-hack-shows-total-compromise-ca-servers-103112/77170/",
        "description": "Fisher, D. (2012, October 31). Final Report on DigiNotar Hack Shows Total Compromise of CA Servers. Retrieved March 6, 2017.",
        "external_id": "none"
      }
    ]
  }
]
