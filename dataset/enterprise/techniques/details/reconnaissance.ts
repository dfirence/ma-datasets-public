export const RECONNAISSANCE_DETAILS = [
  {
    "id": "attack-pattern--5282dd9a-d26d-4e16-88b7-7c0f4553daf4",
    "platform": "pre",
    "tid": "T1589",
    "technique": "Gather Victim Identity Information",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1589.001",
      "T1589.002",
      "T1589.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, etc.) as well as sensitive details such as credentials.<br /><br />Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about victims may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).(Citation: OPM Leak)(Citation: Register Deloitte)(Citation: Register Uber)(Citation: Detectify Slack Tokens)(Citation: Forbes GitHub Creds)(Citation: GitHub truffleHog)(Citation: GitHub Gitrob)(Citation: CNET Leaks) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)).<br /><br />",
    "technique_references": [
      {
        "source_name": "OPM Leak",
        "url": "https://www.opm.gov/cybersecurity/cybersecurity-incidents/",
        "description": "Cybersecurity Resource Center. (n.d.). CYBERSECURITY INCIDENTS. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Register Deloitte",
        "url": "https://www.theregister.com/2017/09/26/deloitte_leak_github_and_google/",
        "description": "Thomson, I. (2017, September 26). Deloitte is a sitting duck: Key systems with RDP open, VPN and proxy 'login details leaked'. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Register Uber",
        "url": "https://www.theregister.com/2015/02/28/uber_subpoenas_github_for_hacker_details/",
        "description": "McCarthy, K. (2015, February 28). FORK ME! Uber hauls GitHub into court to find who hacked database of 50,000 drivers. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Detectify Slack Tokens",
        "url": "https://labs.detectify.com/2016/04/28/slack-bot-token-leakage-exposing-business-critical-information/",
        "description": "Detectify. (2016, April 28). Slack bot token leakage exposing business critical information. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Forbes GitHub Creds",
        "url": "https://www.forbes.com/sites/runasandvik/2014/01/14/attackers-scrape-github-for-cloud-service-credentials-hijack-account-to-mine-virtual-currency/#242c479d3196",
        "description": "Sandvik, R. (2014, January 14). Attackers Scrape GitHub For Cloud Service Credentials, Hijack Account To Mine Virtual Currency. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub truffleHog",
        "url": "https://github.com/dxa4481/truffleHog",
        "description": "Dylan Ayrey. (2016, December 31). truffleHog. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Gitrob",
        "url": "https://github.com/michenriksen/gitrob",
        "description": "Michael Henriksen. (2018, June 9). Gitrob: Putting the Open Source in OSINT. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "CNET Leaks",
        "url": "https://www.cnet.com/news/massive-breach-leaks-773-million-emails-21-million-passwords/",
        "description": "Ng, A. (2019, January 17). Massive breach leaks 773 million email addresses, 21 million passwords. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--9d48cab2-7929-4812-ad22-f536665f0109",
    "platform": "pre",
    "tid": "T1590",
    "technique": "Gather Victim Network Information",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1590.001",
      "T1590.002",
      "T1590.003",
      "T1590.004",
      "T1590.005",
      "T1590.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics regarding its topology and operations.<br /><br />Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about networks may also be exposed to adversaries via online or other accessible data sets (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)).(Citation: WHOIS)(Citation: DNS Dumpster)(Citation: Circl Passive DNS) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).<br /><br />",
    "technique_references": [
      {
        "source_name": "WHOIS",
        "url": "https://www.whois.net/",
        "description": "NTT America. (n.d.). Whois Lookup. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "DNS Dumpster",
        "url": "https://dnsdumpster.com/",
        "description": "Hacker Target. (n.d.). DNS Dumpster. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Circl Passive DNS",
        "url": "https://www.circl.lu/services/passive-dns/",
        "description": "CIRCL Computer Incident Response Center. (n.d.). Passive DNS. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--937e4772-8441-4e4a-8bf0-8d447d667e23",
    "platform": "pre",
    "tid": "T1591",
    "technique": "Gather Victim Org Information",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1591.001",
      "T1591.002",
      "T1591.003",
      "T1591.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operations, as well as the roles and responsibilities of key employees.<br /><br />Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about an organization may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).(Citation: ThreatPost Broadvoice Leak)(Citation: DOB Business Lookup) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).<br /><br />",
    "technique_references": [
      {
        "source_name": "ThreatPost Broadvoice Leak",
        "url": "https://threatpost.com/broadvoice-leaks-350m-records-voicemail-transcripts/160158/",
        "description": "Seals, T. (2020, October 15). Broadvoice Leak Exposes 350M Records, Personal Voicemail Transcripts. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "DOB Business Lookup",
        "url": "https://www.dobsearch.com/business-lookup/",
        "description": "Concert Technologies . (n.d.). Business Lookup - Company Name Search. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--09312b1a-c3c6-4b45-9844-3ccc78e5d82f",
    "platform": "pre",
    "tid": "T1592",
    "technique": "Gather Victim Host Information",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1592.001",
      "T1592.002",
      "T1592.003",
      "T1592.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.).<br /><br />Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Adversaries may also compromise sites then include malicious content designed to collect host information from visitors.(Citation: ATT ScanBox) Information about hosts may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) or [External Remote Services](https://attack.mitre.org/techniques/T1133)).<br /><br />",
    "technique_references": [
      {
        "source_name": "ATT ScanBox",
        "url": "https://cybersecurity.att.com/blogs/labs-research/scanbox-a-reconnaissance-framework-used-on-watering-hole-attacks",
        "description": "Blasco, J. (2014, August 28). Scanbox: A Reconnaissance Framework Used with Watering Hole Attacks. Retrieved October 19, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--a0e6614a-7740-4b24-bd65-f1bde09fc365",
    "platform": "pre",
    "tid": "T1593",
    "technique": "Search Open Websites/Domains",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1593.001",
      "T1593.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search freely available websites and/or domains for information about victims that can be used during targeting. Information about victims may be available in various online sites, such as social media, new sites, or those hosting information about business operations such as hiring or requested/rewarded contracts.(Citation: Cyware Social Media)(Citation: SecurityTrails Google Hacking)(Citation: ExploitDB GoogleHacking)<br /><br />Adversaries may search in different online sites depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Phishing](https://attack.mitre.org/techniques/T1566)).<br /><br />",
    "technique_references": [
      {
        "source_name": "Cyware Social Media",
        "url": "https://cyware.com/news/how-hackers-exploit-social-media-to-break-into-your-company-88e8da8e",
        "description": "Cyware Hacker News. (2019, October 2). How Hackers Exploit Social Media To Break Into Your Company. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "SecurityTrails Google Hacking",
        "url": "https://securitytrails.com/blog/google-hacking-techniques",
        "description": "Borges, E. (2019, March 5). Exploring Google Hacking Techniques. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ExploitDB GoogleHacking",
        "url": "https://www.exploit-db.com/google-hacking-database",
        "description": "Offensive Security. (n.d.). Google Hacking Database. Retrieved October 23, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--16cdd21f-da65-4e4f-bc04-dd7d198c7b26",
    "platform": "pre",
    "tid": "T1594",
    "technique": "Search Victim-Owned Websites",
    "tactic": "reconnaissance",
    "datasources": "web-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites may contain a variety of details, including names of departments/divisions, physical locations, and data about key employees such as names, roles, and contact info (ex: [Email Addresses](https://attack.mitre.org/techniques/T1589/002)). These sites may also have details highlighting business operations and relationships.(Citation: Comparitech Leak)<br /><br />Adversaries may search victim-owned websites to gather actionable information. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Trusted Relationship](https://attack.mitre.org/techniques/T1199) or [Phishing](https://attack.mitre.org/techniques/T1566)).<br /><br />",
    "technique_references": [
      {
        "source_name": "Comparitech Leak",
        "url": "https://www.comparitech.com/blog/vpn-privacy/350-million-customer-records-exposed-online/",
        "description": "Bischoff, P. (2020, October 15). Broadvoice database of more than 350 million customer records exposed online. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--67073dde-d720-45ae-83da-b12d5e73ca3b",
    "platform": "pre",
    "tid": "T1595",
    "technique": "Active Scanning",
    "tactic": "reconnaissance",
    "datasources": "network-device-logs|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1595.001",
      "T1595.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.<br /><br />Adversaries may perform different forms of active scanning depending on what information they seek to gather. These scans can also be performed in various ways, including using native features of network protocols such as ICMP.(Citation: Botnet Scan)(Citation: OWASP Fingerprinting) Information from these scans may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).<br /><br />",
    "technique_references": [
      {
        "source_name": "Botnet Scan",
        "url": "https://www.caida.org/publications/papers/2012/analysis_slash_zero/analysis_slash_zero.pdf",
        "description": "Dainotti, A. et al. (2012). Analysis of a “/0” Stealth Scan from a Botnet. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "OWASP Fingerprinting",
        "url": "https://wiki.owasp.org/index.php/OAT-004_Fingerprinting",
        "description": "OWASP Wiki. (2018, February 16). OAT-004 Fingerprinting. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--55fc4df0-b42c-479a-b860-7a6761bcaad0",
    "platform": "pre",
    "tid": "T1596",
    "technique": "Search Open Technical Databases",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1596.001",
      "T1596.002",
      "T1596.003",
      "T1596.004",
      "T1596.005"
    ],
    "count_subtechniques": 5,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search freely available technical databases for information about victims that can be used during targeting. Information about victims may be available in online databases and repositories, such as registrations of domains/certificates as well as public collections of network data/artifacts gathered from traffic and/or scans.(Citation: WHOIS)(Citation: DNS Dumpster)(Citation: Circl Passive DNS)(Citation: Medium SSL Cert)(Citation: SSLShopper Lookup)(Citation: DigitalShadows CDN)(Citation: Shodan)<br /><br />Adversaries may search in different open databases depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).<br /><br />",
    "technique_references": [
      {
        "source_name": "WHOIS",
        "url": "https://www.whois.net/",
        "description": "NTT America. (n.d.). Whois Lookup. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "DNS Dumpster",
        "url": "https://dnsdumpster.com/",
        "description": "Hacker Target. (n.d.). DNS Dumpster. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Circl Passive DNS",
        "url": "https://www.circl.lu/services/passive-dns/",
        "description": "CIRCL Computer Incident Response Center. (n.d.). Passive DNS. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Medium SSL Cert",
        "url": "https://medium.com/@menakajain/export-download-ssl-certificate-from-server-site-url-bcfc41ea46a2",
        "description": "Jain, M. (2019, September 16). Export & Download — SSL Certificate from Server (Site URL). Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "SSLShopper Lookup",
        "url": "https://www.sslshopper.com/ssl-checker.html",
        "description": "SSL Shopper. (n.d.). SSL Checker. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "DigitalShadows CDN",
        "url": "https://www.digitalshadows.com/blog-and-research/content-delivery-networks-cdns-can-leave-you-exposed-how-you-might-be-affected-and-what-you-can-do-about-it/",
        "description": "Swisscom & Digital Shadows. (2017, September 6). Content Delivery Networks (CDNs) Can Leave You Exposed – How You Might Be Affected And What You Can Do About It. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Shodan",
        "url": "https://shodan.io",
        "description": "Shodan. (n.d.). Shodan. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--a51eb150-93b1-484b-a503-e51453b127a4",
    "platform": "pre",
    "tid": "T1597",
    "technique": "Search Closed Sources",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1597.001",
      "T1597.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search and gather information about victims from closed sources that can be used during targeting. Information about victims may be available for purchase from reputable private sources and databases, such as paid subscriptions to feeds of technical/threat intelligence data.(Citation: D3Secutrity CTI Feeds) Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets.(Citation: ZDNET Selling Data)<br /><br />Adversaries may search in different closed databases depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)).<br /><br />",
    "technique_references": [
      {
        "source_name": "D3Secutrity CTI Feeds",
        "url": "https://d3security.com/blog/10-of-the-best-open-source-threat-intelligence-feeds/",
        "description": "Banerd, W. (2019, April 30). 10 of the Best Open Source Threat Intelligence Feeds. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ZDNET Selling Data",
        "url": "https://www.zdnet.com/article/a-hacker-group-is-selling-more-than-73-million-user-records-on-the-dark-web/",
        "description": "Cimpanu, C. (2020, May 9). A hacker group is selling more than 73 million user records on the dark web. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cca0ccb6-a068-4574-a722-b1556f86833a",
    "platform": "pre",
    "tid": "T1598",
    "technique": "Phishing for Information",
    "tactic": "reconnaissance",
    "datasources": "email-gateway|mail-server|social-media-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1598.001",
      "T1598.002",
      "T1598.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Phishing for information is different from [Phishing](https://attack.mitre.org/techniques/T1566) in that the objective is gathering data from the victim rather than executing malicious code.<br /><br />All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass credential harvesting campaigns.<br /><br />Adversaries may also try to obtain information directly through the exchange of emails, instant messages, or other electronic conversation means.(Citation: ThreatPost Social Media Phishing)(Citation: TrendMictro Phishing)(Citation: PCMag FakeLogin)(Citation: Sophos Attachment)(Citation: GitHub Phishery) Phishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages.<br /><br />",
    "technique_references": [
      {
        "source_name": "ThreatPost Social Media Phishing",
        "url": "https://threatpost.com/facebook-launching-pad-phishing-attacks/160351/",
        "description": "O'Donnell, L. (2020, October 20). Facebook: A Top Launching Pad For Phishing Attacks. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "TrendMictro Phishing",
        "url": "https://www.trendmicro.com/en_us/research/20/i/tricky-forms-of-phishing.html",
        "description": "Babon, P. (2020, September 3). Tricky 'Forms' of Phishing. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "PCMag FakeLogin",
        "url": "https://www.pcmag.com/news/hackers-try-to-phish-united-nations-staffers-with-fake-login-pages",
        "description": "Kan, M. (2019, October 24). Hackers Try to Phish United Nations Staffers With Fake Login Pages. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Sophos Attachment",
        "url": "https://nakedsecurity.sophos.com/2020/10/02/serious-security-phishing-without-links-when-phishers-bring-along-their-own-web-pages/",
        "description": "Ducklin, P. (2020, October 2). Serious Security: Phishing without links – when phishers bring along their own web pages. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Phishery",
        "url": "https://github.com/ryhanson/phishery",
        "description": "Ryan Hanson. (2016, September 24). phishery. Retrieved October 23, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Anti Spoofing",
        "url": "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide",
        "description": "Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ACSC Email Spoofing",
        "url": "https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf",
        "description": "Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved October 19, 2020.",
        "external_id": "none"
      }
    ]
  }
]
