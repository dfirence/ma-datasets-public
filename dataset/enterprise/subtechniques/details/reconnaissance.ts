export const RECONNAISSANCE_SUBTECHNIQUE_DETAILS = [
  {
    "id": "attack-pattern--bc76d0a4-db11-4551-9ac4-01a469cfb161",
    "platform": "pre",
    "tid": "T1589.001",
    "technique": "Credentials",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather credentials that can be used during targeting. Account credentials gathered by adversaries may be those directly associated with the target victim organization or attempt to take advantage of the tendency for users to use the same passwords across personal and business accounts.<br /><br />Adversaries may gather credentials from potential victims in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Adversaries may also compromise sites then include malicious content designed to collect website authentication cookies from visitors.(Citation: ATT ScanBox) Credential information may also be exposed to adversaries via leaks to online or other accessible data sets (ex: [Search Engines](https://attack.mitre.org/techniques/T1593/002), breach dumps, code repositories, etc.).(Citation: Register Deloitte)(Citation: Register Uber)(Citation: Detectify Slack Tokens)(Citation: Forbes GitHub Creds)(Citation: GitHub truffleHog)(Citation: GitHub Gitrob)(Citation: CNET Leaks) Adversaries may also purchase credentials from dark web or other black-markets. Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)).<br /><br />",
    "technique_references": [
      {
        "source_name": "ATT ScanBox",
        "url": "https://cybersecurity.att.com/blogs/labs-research/scanbox-a-reconnaissance-framework-used-on-watering-hole-attacks",
        "description": "Blasco, J. (2014, August 28). Scanbox: A Reconnaissance Framework Used with Watering Hole Attacks. Retrieved October 19, 2020.",
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
    "id": "attack-pattern--69f897fd-12a9-4c89-ad6a-46d2f3c38262",
    "platform": "pre",
    "tid": "T1589.002",
    "technique": "Email Addresses",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather email addresses that can be used during targeting. Even if internal instances exist, organizations may have public-facing email infrastructure and addresses for employees.<br /><br />Adversaries may easily gather email addresses, since they may be readily available and exposed via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).(Citation: HackersArise Email)(Citation: CNET Leaks) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Email Accounts](https://attack.mitre.org/techniques/T1586/002)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566)).<br /><br />",
    "technique_references": [
      {
        "source_name": "HackersArise Email",
        "url": "https://www.hackers-arise.com/email-scraping-and-maltego",
        "description": "Hackers Arise. (n.d.). Email Scraping and Maltego. Retrieved October 20, 2020.",
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
    "id": "attack-pattern--76551c52-b111-4884-bc47-ff3e728f0156",
    "platform": "pre",
    "tid": "T1589.003",
    "technique": "Employee Names",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather employee names that can be used during targeting. Employee names be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures.<br /><br />Adversaries may easily gather employee names, since they may be readily available and exposed via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).(Citation: OPM Leak) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)).<br /><br />",
    "technique_references": [
      {
        "source_name": "OPM Leak",
        "url": "https://www.opm.gov/cybersecurity/cybersecurity-incidents/",
        "description": "Cybersecurity Resource Center. (n.d.). CYBERSECURITY INCIDENTS. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e3b168bd-fcd7-439e-9382-2e6c2f63514d",
    "platform": "pre",
    "tid": "T1590.001",
    "technique": "Domain Properties",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's network domain(s) that can be used during targeting. Information about domains and their properties may include a variety of details, including what domain(s) the victim owns as well as administrative data (ex: name, registrar, etc.) and more directly actionable information such as contacts (email addresses and phone numbers), business addresses, and name servers.<br /><br />Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about victim domains and their properties may also be exposed to adversaries via online or other accessible data sets (ex: [WHOIS](https://attack.mitre.org/techniques/T1596/002)).(Citation: WHOIS)(Citation: DNS Dumpster)(Citation: Circl Passive DNS) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596), [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593), or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566)).<br /><br />",
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
    "id": "attack-pattern--0ff59227-8aa8-4c09-bf1f-925605bd07ea",
    "platform": "pre",
    "tid": "T1590.002",
    "technique": "DNS",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts.<br /><br />Adversaries may gather this information in various ways, such as querying or otherwise collecting details via [DNS/Passive DNS](https://attack.mitre.org/techniques/T1596/001). DNS information may also be exposed to adversaries via online or other accessible data sets (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)).(Citation: DNS Dumpster)(Citation: Circl Passive DNS) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596), [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593), or [Active Scanning](https://attack.mitre.org/techniques/T1595)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)).<br /><br />",
    "technique_references": [
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
    "id": "attack-pattern--36aa137f-5166-41f8-b2f0-a4cfa1b4133e",
    "platform": "pre",
    "tid": "T1590.003",
    "technique": "Network Trust Dependencies",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's network trust dependencies that can be used during targeting. Information about network trusts may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access.<br /><br />Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about network trusts may also be exposed to adversaries via online or other accessible data sets (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)).(Citation: Pentesting AD Forests) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).<br /><br />",
    "technique_references": [
      {
        "source_name": "Pentesting AD Forests",
        "url": "https://www.slideshare.net/rootedcon/carlos-garca-pentesting-active-directory-forests-rooted2019",
        "description": "García, C. (2019, April 3). Pentesting Active Directory Forests. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--34ab90a3-05f6-4259-8f21-621081fdaba5",
    "platform": "pre",
    "tid": "T1590.004",
    "technique": "Network Topology",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's network topology that can be used during targeting. Information about network topologies may include a variety of details, including the physical and/or logical arrangement of both external-facing and internal network environments. This information may also include specifics regarding network devices (gateways, routers, etc.) and other infrastructure.<br /><br />Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about network topologies may also be exposed to adversaries via online or other accessible data sets (ex: [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).(Citation: DNS Dumpster) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)).<br /><br />",
    "technique_references": [
      {
        "source_name": "DNS Dumpster",
        "url": "https://dnsdumpster.com/",
        "description": "Hacker Target. (n.d.). DNS Dumpster. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0dda99f0-4701-48ca-9774-8504922e92d3",
    "platform": "pre",
    "tid": "T1590.005",
    "technique": "IP Addresses",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather the victim's IP addresses that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses. Information about assigned IP addresses may include a variety of details, such as which IP addresses are in use. IP addresses may also enable an adversary to derive other details about a victim, such as organizational size, physical location(s), Internet service provider, and or where/how their publicly-facing infrastructure is hosted.<br /><br />Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about assigned IP addresses may also be exposed to adversaries via online or other accessible data sets (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)).(Citation: WHOIS)(Citation: DNS Dumpster)(Citation: Circl Passive DNS) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)).<br /><br />",
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
    "id": "attack-pattern--6c2957f9-502a-478c-b1dd-d626c0659413",
    "platform": "pre",
    "tid": "T1590.006",
    "technique": "Network Security Appliances",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's network security appliances that can be used during targeting. Information about network security appliances may include a variety of details, such as the existence and specifics of deployed firewalls, content filters, and proxies/bastion hosts. Adversaries may also target information about victim network-based intrusion detection systems (NIDS) or other appliances related to defensive cybersecurity operations.<br /><br />Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598).(Citation: Nmap Firewalls NIDS) Information about network security appliances may also be exposed to adversaries via online or other accessible data sets (ex: [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)).<br /><br />",
    "technique_references": [
      {
        "source_name": "Nmap Firewalls NIDS",
        "url": "https://nmap.org/book/firewalls.html",
        "description": "Nmap. (n.d.). Chapter 10. Detecting and Subverting Firewalls and Intrusion Detection Systems. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ed730f20-0e44-48b9-85f8-0e2adeb76867",
    "platform": "pre",
    "tid": "T1591.001",
    "technique": "Determine Physical Locations",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather the victim's physical location(s) that can be used during targeting. Information about physical locations of a target organization may include a variety of details, including where key resources and infrastructure are housed. Physical locations may also indicate what legal jurisdiction and/or authorities the victim operates within.<br /><br />Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Physical locations of a target organization may also be exposed to adversaries via online or other accessible data sets (ex: [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594) or [Social Media](https://attack.mitre.org/techniques/T1593/001)).(Citation: ThreatPost Broadvoice Leak)(Citation: DOB Business Lookup) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Hardware Additions](https://attack.mitre.org/techniques/T1200)).<br /><br />",
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
    "id": "attack-pattern--6ee2dc99-91ad-4534-a7d8-a649358c331f",
    "platform": "pre",
    "tid": "T1591.002",
    "technique": "Business Relationships",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's business relationships that can be used during targeting. Information about an organization’s business relationships may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access. This information may also reveal supply chains and shipment paths for the victim’s hardware and software resources.<br /><br />Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about business relationships may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).(Citation: ThreatPost Broadvoice Leak) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195), [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).<br /><br />",
    "technique_references": [
      {
        "source_name": "ThreatPost Broadvoice Leak",
        "url": "https://threatpost.com/broadvoice-leaks-350m-records-voicemail-transcripts/160158/",
        "description": "Seals, T. (2020, October 15). Broadvoice Leak Exposes 350M Records, Personal Voicemail Transcripts. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--2339cf19-8f1e-48f7-8a91-0262ba547b6f",
    "platform": "pre",
    "tid": "T1591.003",
    "technique": "Identify Business Tempo",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization’s business tempo may include a variety of details, including operational hours/days of the week. This information may also reveal times/dates of purchases and shipments of the victim’s hardware and software resources.<br /><br />Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about business tempo may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).(Citation: ThreatPost Broadvoice Leak) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199))<br /><br />",
    "technique_references": [
      {
        "source_name": "ThreatPost Broadvoice Leak",
        "url": "https://threatpost.com/broadvoice-leaks-350m-records-voicemail-transcripts/160158/",
        "description": "Seals, T. (2020, October 15). Broadvoice Leak Exposes 350M Records, Personal Voicemail Transcripts. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cc723aff-ec88-40e3-a224-5af9fd983cc4",
    "platform": "pre",
    "tid": "T1591.004",
    "technique": "Identify Roles",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about identities and roles within the victim organization that can be used during targeting. Information about business roles may reveal a variety of targetable details, including identifiable information for key personnel as well as what data/resources they have access to.<br /><br />Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about business roles may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).(Citation: ThreatPost Broadvoice Leak) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566)).<br /><br />",
    "technique_references": [
      {
        "source_name": "ThreatPost Broadvoice Leak",
        "url": "https://threatpost.com/broadvoice-leaks-350m-records-voicemail-transcripts/160158/",
        "description": "Seals, T. (2020, October 15). Broadvoice Leak Exposes 350M Records, Personal Voicemail Transcripts. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--24286c33-d4a4-4419-85c2-1d094a896c26",
    "platform": "pre",
    "tid": "T1592.001",
    "technique": "Hardware",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's host hardware that can be used during targeting. Information about hardware infrastructure may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: card/biometric readers, dedicated encryption hardware, etc.).<br /><br />Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) (ex: hostnames, server banners, user agent strings) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Adversaries may also compromise sites then include malicious content designed to collect host information from visitors.(Citation: ATT ScanBox) Information about the hardware infrastructure may also be exposed to adversaries via online or other accessible data sets (ex: job postings, network maps, assessment reports, resumes, or purchase invoices). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Compromise Hardware Supply Chain](https://attack.mitre.org/techniques/T1195/003) or [Hardware Additions](https://attack.mitre.org/techniques/T1200)).<br /><br />",
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
    "id": "attack-pattern--baf60e1a-afe5-4d31-830f-1b1ba2351884",
    "platform": "pre",
    "tid": "T1592.002",
    "technique": "Software",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's host software that can be used during targeting. Information about installed software may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: antivirus, SIEMs, etc.).<br /><br />Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) (ex: listening ports, server banners, user agent strings) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Adversaries may also compromise sites then include malicious content designed to collect host information from visitors.(Citation: ATT ScanBox) Information about the installed software may also be exposed to adversaries via online or other accessible data sets (ex: job postings, network maps, assessment reports, resumes, or purchase invoices). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or for initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) or [External Remote Services](https://attack.mitre.org/techniques/T1133)).<br /><br />",
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
    "id": "attack-pattern--b85f6ce5-81e8-4f36-aff2-3df9d02a9c9d",
    "platform": "pre",
    "tid": "T1592.003",
    "technique": "Firmware",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's host firmware that can be used during targeting. Information about host firmware may include a variety of details such as type and versions on specific hosts, which may be used to infer more information about hosts in the environment (ex: configuration, purpose, age/patch level, etc.).<br /><br />Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about host firmware may only be exposed to adversaries via online or other accessible data sets (ex: job postings, network maps, assessment reports, resumes, or purchase invoices).(Citation: ArsTechnica Intel) Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) or [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).<br /><br />",
    "technique_references": [
      {
        "source_name": "ArsTechnica Intel",
        "url": "https://arstechnica.com/information-technology/2020/08/intel-is-investigating-the-leak-of-20gb-of-its-source-code-and-private-data/",
        "description": "Goodin, D. & Salter, J. (2020, August 6). More than 20GB of Intel source code and proprietary data dumped online. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--774ad5bb-2366-4c13-a8a9-65e50b292e7c",
    "platform": "pre",
    "tid": "T1592.004",
    "technique": "Client Configurations",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may gather information about the victim's client configurations that can be used during targeting. Information about client configurations may include a variety of details and settings, including operating system/version, virtualization, architecture (ex: 32 or 64 bit), language, and/or time zone.<br /><br />Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) (ex: listening ports, server banners, user agent strings) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Adversaries may also compromise sites then include malicious content designed to collect host information from visitors.(Citation: ATT ScanBox) Information about the client configurations may also be exposed to adversaries via online or other accessible data sets (ex: job postings, network maps, assessment reports, resumes, or purchase invoices). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) or [External Remote Services](https://attack.mitre.org/techniques/T1133)).<br /><br />",
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
    "id": "attack-pattern--bbe5b322-e2af-4a5e-9625-a4e62bf84ed3",
    "platform": "pre",
    "tid": "T1593.001",
    "technique": "Social Media",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search social media for information about victims that can be used during targeting. Social media sites may contain various information about a victim organization, such as business announcements as well as information about the roles, locations, and interests of staff.<br /><br />Adversaries may search in different social media sites depending on what information they seek to gather. Threat actors may passively harvest data from these sites, as well as use information gathered to create fake profiles/groups to elicit victim’s into revealing specific information (i.e. [Spearphishing Service](https://attack.mitre.org/techniques/T1598/001)).(Citation: Cyware Social Media) Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)).<br /><br />",
    "technique_references": [
      {
        "source_name": "Cyware Social Media",
        "url": "https://cyware.com/news/how-hackers-exploit-social-media-to-break-into-your-company-88e8da8e",
        "description": "Cyware Hacker News. (2019, October 2). How Hackers Exploit Social Media To Break Into Your Company. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--6e561441-8431-4773-a9b8-ccf28ef6a968",
    "platform": "pre",
    "tid": "T1593.002",
    "technique": "Search Engines",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may use search engines to collect information about victims that can be used during targeting. Search engine services typical crawl online sites to index context and may provide users with specialized syntax to search for specific keywords or specific types of content (i.e. filetypes).(Citation: SecurityTrails Google Hacking)(Citation: ExploitDB GoogleHacking)<br /><br />Adversaries may craft various search engine queries depending on what information they seek to gather. Threat actors may use search engines to harvest general information about victims, as well as use specialized queries to look for spillages/leaks of sensitive information such as network details or credentials. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Valid Accounts](https://attack.mitre.org/techniques/T1078) or [Phishing](https://attack.mitre.org/techniques/T1566)).<br /><br />",
    "technique_references": [
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
    "id": "attack-pattern--db8f5003-3b20-48f0-9b76-123e44208120",
    "platform": "pre",
    "tid": "T1595.001",
    "technique": "Scanning IP Blocks",
    "tactic": "reconnaissance",
    "datasources": "network-device-logs|packet-capture",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may scan victim IP blocks to gather information that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses.<br /><br />Adversaries may scan IP blocks in order to [Gather Victim Network Information](https://attack.mitre.org/techniques/T1590), such as which IP addresses are actively in use as well as more detailed information about hosts assigned these addresses. Scans may range from simple pings (ICMP requests and responses) to more nuanced scans that may reveal host software/versions via server banners or other network artifacts.(Citation: Botnet Scan) Information from these scans may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)).<br /><br />",
    "technique_references": [
      {
        "source_name": "Botnet Scan",
        "url": "https://www.caida.org/publications/papers/2012/analysis_slash_zero/analysis_slash_zero.pdf",
        "description": "Dainotti, A. et al. (2012). Analysis of a “/0” Stealth Scan from a Botnet. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--5502c4e9-24ef-4d5f-8ee9-9e906c2f82c4",
    "platform": "pre",
    "tid": "T1595.002",
    "technique": "Vulnerability Scanning",
    "tactic": "reconnaissance",
    "datasources": "network-device-logs|packet-capture",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check if the configuration of a target host/application (ex: software and version) potentially aligns with the target of a specific exploit the adversary may seek to use.<br /><br />These scans may also include more broad attempts to [Gather Victim Host Information](https://attack.mitre.org/techniques/T1592) that can be used to identify more commonly known, exploitable vulnerabilities. Vulnerability scans typically harvest running software and version numbers via server banners, listening ports, or other network artifacts.(Citation: OWASP Vuln Scanning) Information from these scans may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).<br /><br />",
    "technique_references": [
      {
        "source_name": "OWASP Vuln Scanning",
        "url": "https://wiki.owasp.org/index.php/OAT-014_Vulnerability_Scanning",
        "description": "OWASP Wiki. (2018, February 16). OAT-014 Vulnerability Scanning. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--17fd695c-b88c-455a-a3d1-43b6cb728532",
    "platform": "pre",
    "tid": "T1596.001",
    "technique": "DNS/Passive DNS",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search DNS data for information about victims that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts.<br /><br />Adversaries may search DNS data to gather actionable information. Threat actors can query nameservers for a target organization directly, or search through centralized repositories of logged DNS query responses (known as passive DNS).(Citation: DNS Dumpster)(Citation: Circl Passive DNS) Adversaries may also seek and target DNS misconfigurations/leaks that reveal information about internal networks. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).<br /><br />",
    "technique_references": [
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
    "id": "attack-pattern--166de1c6-2814-4fe5-8438-4e80f76b169f",
    "platform": "pre",
    "tid": "T1596.002",
    "technique": "WHOIS",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search public WHOIS data for information about victims that can be used during targeting. WHOIS data is stored by regional Internet registries (RIR) responsible for allocating and assigning Internet resources such as domain names. Anyone can query WHOIS servers for information about a registered domain, such as assigned IP blocks, contact information, and DNS nameservers.(Citation: WHOIS)<br /><br />Adversaries may search WHOIS data to gather actionable information. Threat actors can use online resources or command-line utilities to pillage through WHOIS data for information about potential victims. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).<br /><br />",
    "technique_references": [
      {
        "source_name": "WHOIS",
        "url": "https://www.whois.net/",
        "description": "NTT America. (n.d.). Whois Lookup. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0979abf9-4e26-43ec-9b6e-54efc4e70fca",
    "platform": "pre",
    "tid": "T1596.003",
    "technique": "Digital Certificates",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search public digital certificate data for information about victims that can be used during targeting. Digital certificates are issued by a certificate authority (CA) in order to cryptographically verify the origin of signed content. These certificates, such as those used for encrypted web traffic (HTTPS SSL/TLS communications), contain information about the registered organization such as name and location.<br /><br />Adversaries may search digital certificate data to gather actionable information. Threat actors can use online resources and lookup tools to harvest information about certificates.(Citation: SSLShopper Lookup) Digital certificate data may also be available from artifacts signed by the organization (ex: certificates used from encrypted web traffic are served with content).(Citation: Medium SSL Cert) Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).<br /><br />",
    "technique_references": [
      {
        "source_name": "SSLShopper Lookup",
        "url": "https://www.sslshopper.com/ssl-checker.html",
        "description": "SSL Shopper. (n.d.). SSL Checker. Retrieved October 20, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Medium SSL Cert",
        "url": "https://medium.com/@menakajain/export-download-ssl-certificate-from-server-site-url-bcfc41ea46a2",
        "description": "Jain, M. (2019, September 16). Export & Download — SSL Certificate from Server (Site URL). Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--91177e6d-b616-4a03-ba4b-f3b32f7dda75",
    "platform": "pre",
    "tid": "T1596.004",
    "technique": "CDNs",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search content delivery network (CDN) data about victims that can be used during targeting. CDNs allow an organization to host content from a distributed, load balanced array of servers. CDNs may also allow organizations to customize content delivery based on the requestor’s geographical region.<br /><br />Adversaries may search CDN data to gather actionable information. Threat actors can use online resources and lookup tools to harvest information about content servers within a CDN. Adversaries may also seek and target CDN misconfigurations that leak sensitive information not intended to be hosted and/or do not have the same protection mechanisms (ex: login portals) as the content hosted on the organization’s website.(Citation: DigitalShadows CDN) Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [Drive-by Compromise](https://attack.mitre.org/techniques/T1189)).<br /><br />",
    "technique_references": [
      {
        "source_name": "DigitalShadows CDN",
        "url": "https://www.digitalshadows.com/blog-and-research/content-delivery-networks-cdns-can-leave-you-exposed-how-you-might-be-affected-and-what-you-can-do-about-it/",
        "description": "Swisscom & Digital Shadows. (2017, September 6). Content Delivery Networks (CDNs) Can Leave You Exposed – How You Might Be Affected And What You Can Do About It. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ec4be82f-940c-4dcb-87fe-2bbdd17c692f",
    "platform": "pre",
    "tid": "T1596.005",
    "technique": "Scan Databases",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search within public scan databases for information about victims that can be used during targeting. Various online services continuously publish the results of Internet scans/surveys, often harvesting information such as active IP addresses, hostnames, open ports, certificates, and even server banners.(Citation: Shodan)<br /><br />Adversaries may search scan databases to gather actionable information. Threat actors can use online resources and lookup tools to harvest information from these services. Adversaries may seek information about their already identified targets, or use these datasets to discover opportunities for successful breaches. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).<br /><br />",
    "technique_references": [
      {
        "source_name": "Shodan",
        "url": "https://shodan.io",
        "description": "Shodan. (n.d.). Shodan. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--51e54974-a541-4fb6-a61b-0518e4c6de41",
    "platform": "pre",
    "tid": "T1597.001",
    "technique": "Threat Intel Vendors",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may search private data from threat intelligence vendors for information that can be used during targeting. Threat intelligence vendors may offer paid feeds or portals that offer more data than what is publicly reported. Although sensitive details (such as customer names and other identifiers) may be redacted, this information may contain trends regarding breaches such as target industries, attribution claims, and successful TTPs/countermeasures.(Citation: D3Secutrity CTI Feeds)<br /><br />Adversaries may search in private threat intelligence vendor data to gather actionable information. Threat actors may seek information/indicators gathered about their own campaigns, as well as those conducted by other adversaries that may align with their target industries, capabilities/objectives, or other operational concerns. Information reported by vendors may also reveal opportunities other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) or [External Remote Services](https://attack.mitre.org/techniques/T1133)).<br /><br />",
    "technique_references": [
      {
        "source_name": "D3Secutrity CTI Feeds",
        "url": "https://d3security.com/blog/10-of-the-best-open-source-threat-intelligence-feeds/",
        "description": "Banerd, W. (2019, April 30). 10 of the Best Open Source Threat Intelligence Feeds. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0a241b6c-7bb2-48f9-98f7-128145b4d27f",
    "platform": "pre",
    "tid": "T1597.002",
    "technique": "Purchase Technical Data",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may purchase technical information about victims that can be used during targeting. Information about victims may be available for purchase within reputable private sources and databases, such as paid subscriptions to feeds of scan databases or other data aggregation services. Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets.<br /><br />Adversaries may purchase information about their already identified targets, or use purchased data to discover opportunities for successful breaches. Threat actors may gather various technical details from purchased data, including but not limited to employee contact information, credentials, or specifics regarding a victim’s infrastructure.(Citation: ZDNET Selling Data) Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)).<br /><br />",
    "technique_references": [
      {
        "source_name": "ZDNET Selling Data",
        "url": "https://www.zdnet.com/article/a-hacker-group-is-selling-more-than-73-million-user-records-on-the-dark-web/",
        "description": "Cimpanu, C. (2020, May 9). A hacker group is selling more than 73 million user records on the dark web. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f870408c-b1cd-49c7-a5c7-0ef0fc496cc6",
    "platform": "pre",
    "tid": "T1598.001",
    "technique": "Spearphishing Service",
    "tactic": "reconnaissance",
    "datasources": "none",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages.<br /><br />All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services.(Citation: ThreatPost Social Media Phishing) These services are more likely to have a less-strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries may create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and information about their environment. Adversaries may also use information from previous reconnaissance efforts (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)) to craft persuasive and believable lures.<br /><br />",
    "technique_references": [
      {
        "source_name": "ThreatPost Social Media Phishing",
        "url": "https://threatpost.com/facebook-launching-pad-phishing-attacks/160351/",
        "description": "O'Donnell, L. (2020, October 20). Facebook: A Top Launching Pad For Phishing Attacks. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--8982a661-d84c-48c0-b4ec-1db29c6cf3bc",
    "platform": "pre",
    "tid": "T1598.002",
    "technique": "Spearphishing Attachment",
    "tactic": "reconnaissance",
    "datasources": "email-gateway|mail-server",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages.<br /><br />All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon the recipient populating information then returning the file.(Citation: Sophos Attachment)(Citation: GitHub Phishery) The text of the spearphishing email usually tries to give a plausible reason why the file should be filled-in, such as a request for information from a business associate. Adversaries may also use information from previous reconnaissance efforts (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)) to craft persuasive and believable lures.<br /><br />",
    "technique_references": [
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
  },
  {
    "id": "attack-pattern--2d3f5b3c-54ca-4f4d-bb1f-849346d31230",
    "platform": "pre",
    "tid": "T1598.003",
    "technique": "Spearphishing Link",
    "tactic": "reconnaissance",
    "datasources": "email-gateway|mail-server",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages.<br /><br />All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, the malicious emails contain links generally accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser.(Citation: TrendMictro Phishing)(Citation: PCMag FakeLogin) The given website may closely resemble a legitimate site in appearance and have a URL containing elements from the real site. From the fake website, information is gathered in web forms and sent to the attacker. Adversaries may also use information from previous reconnaissance efforts (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)) to craft persuasive and believable lures.<br /><br />",
    "technique_references": [
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
