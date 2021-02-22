 [
  {
    "id": "attack-pattern--40f5caa0-4cb7-4117-89fc-d421bb493df3",
    "platform": "pre",
    "tid": "T1583.001",
    "technique": "Domains",
    "tactic": "resource-development",
    "datasources": "domain-registration",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may purchase domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or, in some cases, acquired for free.<br /><br />Adversaries can use purchased domains for a variety of purposes, including for [Phishing](https://attack.mitre.org/techniques/T1566), [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), and Command and Control.(Citation: CISA MSS Sep 2020) Adversaries may choose domains that are similar to legitimate domains, including through use of homoglyphs or use of a different top-level domain (TLD).(Citation: FireEye APT28)(Citation: PaypalScam) Typosquatting may be used to aid in delivery of payloads via [Drive-by Compromise](https://attack.mitre.org/techniques/T1189). Adversaries can also use internationalized domain names (IDNs) to create visually similar lookalike domains for use in operations.(Citation: CISA IDN ST05-016)<br /><br />Domain registrars each maintain a publicly viewable database that displays contact information for every registered domain. Private WHOIS services display alternative information, such as their own company data, rather than the owner of the domain. Adversaries may use such private WHOIS services to obscure information about who owns a purchased domain. Adversaries may further interrupt efforts to track their infrastructure by using varied registration information and purchasing domains with different domain registrars.(Citation: Mandiant APT1)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/630.html",
        "description": "none",
        "external_id": "CAPEC-630"
      },
      {
        "source_name": "CISA MSS Sep 2020",
        "url": "https://us-cert.cisa.gov/ncas/alerts/aa20-258a",
        "description": "CISA. (2020, September 14). Alert (AA20-258A): Chinese Ministry of State Security-Affiliated Cyber Threat Actor Activity. Retrieved October 1, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye APT28",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf",
        "description": "FireEye. (2015). APT28: A WINDOW INTO RUSSIA’S CYBER ESPIONAGE OPERATIONS?. Retrieved August 19, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "PaypalScam",
        "url": "https://www.zdnet.com/article/paypal-alert-beware-the-paypai-scam-5000109103/",
        "description": "Bob Sullivan. (2000, July 24). PayPal alert! Beware the 'PaypaI' scam. Retrieved March 2, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "CISA IDN ST05-016",
        "url": "https://us-cert.cisa.gov/ncas/tips/ST05-016",
        "description": "CISA. (2019, September 27). Security Tip (ST05-016): Understanding Internationalized Domain Names. Retrieved October 20, 2020.",
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
    "id": "attack-pattern--197ef1b9-e764-46c3-b96c-23f77985dc81",
    "platform": "pre",
    "tid": "T1583.002",
    "technique": "DNS Server",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may set up their own Domain Name System (DNS) servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)). Instead of hijacking existing DNS servers, adversaries may opt to configure and run their own DNS servers in support of operations.<br /><br />By running their own DNS servers, adversaries can have more control over how they administer server-side DNS C2 traffic ([DNS](https://attack.mitre.org/techniques/T1071/004)). With control over a DNS server, adversaries can configure DNS applications to provide conditional responses to malware and, generally, have more flexibility in the structure of the DNS-based C2 channel.(Citation: Unit42 DNS Mar 2019)<br /><br />",
    "technique_references": [
      {
        "source_name": "Unit42 DNS Mar 2019",
        "url": "https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/",
        "description": "Hinchliffe, A. (2019, March 15). DNS Tunneling: how DNS can be (ab)used by malicious actors. Retrieved October 3, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--79da0971-3147-4af6-a4f5-e8cd447cd795",
    "platform": "pre",
    "tid": "T1583.003",
    "technique": "Virtual Private Server",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may rent Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. By utilizing a VPS, adversaries can make it difficult to physically tie back operations to them. The use of cloud infrastructure can also make it easier for adversaries to rapidly provision, modify, and shut down their infrastructure.<br /><br />Acquiring a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow adversaries to benefit from the ubiquity and trust associated with higher reputation cloud service providers. Adversaries may also acquire infrastructure from VPS service providers that are known for renting VPSs with minimal registration information, allowing for more anonymous acquisitions of infrastructure.(Citation: TrendmicroHideoutsLease)<br /><br />",
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
    "id": "attack-pattern--60c4b628-4807-4b0b-bbf5-fdac8643c337",
    "platform": "pre",
    "tid": "T1583.004",
    "technique": "Server",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may buy, lease, or rent physical servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, including for Command and Control. Instead of compromising a third-party [Server](https://attack.mitre.org/techniques/T1584/004) or renting a [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003), adversaries may opt to configure and run their own servers in support of operations.<br /><br />Adversaries may only need a lightweight setup if most of their activities will take place using online infrastructure. Or, they may need to build extensive infrastructure if they want to test, communicate, and control other aspects of their activities on their own systems.(Citation: NYTStuxnet)<br /><br />",
    "technique_references": [
      {
        "source_name": "NYTStuxnet",
        "url": "https://www.nytimes.com/2011/01/16/world/middleeast/16stuxnet.html",
        "description": "William J. Broad, John Markoff, and David E. Sanger. (2011, January 15). Israeli Test on Worm Called Crucial in Iran Nuclear Delay. Retrieved March 1, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--31225cd3-cd46-4575-b287-c2c14011c074",
    "platform": "pre",
    "tid": "T1583.005",
    "technique": "Botnet",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may buy, lease, or rent a network of compromised systems that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks.(Citation: Norton Botnet) Adversaries may purchase a subscription to use an existing botnet from a booter/stresser service. With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale [Phishing](https://attack.mitre.org/techniques/T1566) or Distributed Denial of Service (DDoS).(Citation: Imperva DDoS for Hire)(Citation: Krebs-Anna)(Citation: Krebs-Bazaar)(Citation: Krebs-Booter)<br /><br />",
    "technique_references": [
      {
        "source_name": "Norton Botnet",
        "url": "https://us.norton.com/internetsecurity-malware-what-is-a-botnet.html",
        "description": "Norton. (n.d.). What is a botnet?. Retrieved October 4, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Imperva DDoS for Hire",
        "url": "https://www.imperva.com/learn/ddos/booters-stressers-ddosers/",
        "description": "Imperva. (n.d.). Booters, Stressers and DDoSers. Retrieved October 4, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Krebs-Anna",
        "url": "https://krebsonsecurity.com/2017/01/who-is-anna-senpai-the-mirai-worm-author/",
        "description": "Brian Krebs. (2017, January 18). Who is Anna-Senpai, the Mirai Worm Author?. Retrieved May 15, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Krebs-Bazaar",
        "url": "https://krebsonsecurity.com/2016/10/hackforums-shutters-booter-service-bazaar/",
        "description": "Brian Krebs. (2016, October 31). Hackforums Shutters Booter Service Bazaar. Retrieved May 15, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Krebs-Booter",
        "url": "https://krebsonsecurity.com/2016/10/are-the-days-of-booter-services-numbered/",
        "description": "Brian Krebs. (2016, October 27). Are the Days of “Booter” Services Numbered?. Retrieved May 15, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--88d31120-5bc7-4ce3-a9c0-7cf147be8e54",
    "platform": "pre",
    "tid": "T1583.006",
    "technique": "Web Services",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may register for web services that can be used during targeting. A variety of popular websites exist for adversaries to register for a web-based service that can be abused during later stages of the adversary lifecycle, such as during Command and Control ([Web Service](https://attack.mitre.org/techniques/T1102)) or [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567). Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. By utilizing a web service, adversaries can make it difficult to physically tie back operations to them.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--f9cc4d06-775f-4ee1-b401-4e2cc0da30ba",
    "platform": "pre",
    "tid": "T1584.001",
    "technique": "Domains",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may hijack domains and/or subdomains that can be used during targeting. Domain registration hijacking is the act of changing the registration of a domain name without the permission of the original registrant.(Citation: ICANNDomainNameHijacking) An adversary may gain access to an email account for the person listed as the owner of the domain. The adversary can then claim that they forgot their password in order to make changes to the domain registration. Other possibilities include social engineering a domain registration help desk to gain access to an account or taking advantage of renewal process gaps.<br /><br />Subdomain hijacking can occur when organizations have DNS entries that point to non-existent or deprovisioned resources. In such cases, an adversary may take control of a subdomain to conduct operations with the benefit of the trust associated with that domain.(Citation: Microsoft Sub Takeover 2020)<br /><br />",
    "technique_references": [
      {
        "source_name": "ICANNDomainNameHijacking",
        "url": "https://www.icann.org/groups/ssac/documents/sac-007-en",
        "description": "ICANN Security and Stability Advisory Committee. (2005, July 12). Domain Name Hijacking: Incidents, Threats, Risks and Remediation. Retrieved March 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Sub Takeover 2020",
        "url": "https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
        "description": "Microsoft. (2020, September 29). Prevent dangling DNS entries and avoid subdomain takeover. Retrieved October 12, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--c2f59d25-87fe-44aa-8f83-e8e59d077bf5",
    "platform": "pre",
    "tid": "T1584.002",
    "technique": "DNS Server",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may compromise third-party DNS servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)). Instead of setting up their own DNS servers, adversaries may compromise third-party DNS servers in support of operations.<br /><br />By compromising DNS servers, adversaries can alter DNS records. Such control can allow for redirection of an organization's traffic, facilitating Collection and Credential Access efforts for the adversary.(Citation: Talos DNSpionage Nov 2018)(Citation: FireEye DNS Hijack 2019) Adversaries may also be able to silently create subdomains pointed at malicious servers without tipping off the actual owner of the DNS server.(Citation: CiscoAngler)(Citation: Proofpoint Domain Shadowing)<br /><br />",
    "technique_references": [
      {
        "source_name": "Talos DNSpionage Nov 2018",
        "url": "https://blog.talosintelligence.com/2018/11/dnspionage-campaign-targets-middle-east.html",
        "description": "Mercer, W., Rascagneres, P. (2018, November 27). DNSpionage Campaign Targets Middle East. Retrieved October 9, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye DNS Hijack 2019",
        "url": "https://www.fireeye.com/blog/threat-research/2019/01/global-dns-hijacking-campaign-dns-record-manipulation-at-scale.html",
        "description": "Hirani, M., Jones, S., Read, B. (2019, January 10). Global DNS Hijacking Campaign: DNS Record Manipulation at Scale. Retrieved October 9, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "CiscoAngler",
        "url": "https://blogs.cisco.com/security/talos/angler-domain-shadowing",
        "description": "Nick Biasini. (2015, March 3). Threat Spotlight: Angler Lurking in the Domain Shadows. Retrieved March 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Proofpoint Domain Shadowing",
        "url": "https://www.proofpoint.com/us/threat-insight/post/The-Shadow-Knows",
        "description": "Proofpoint Staff. (2015, December 15). The shadow knows: Malvertising campaigns use domain shadowing to pull in Angler EK. Retrieved October 16, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--39cc9f64-cf74-4a48-a4d8-fe98c54a02e0",
    "platform": "pre",
    "tid": "T1584.003",
    "technique": "Virtual Private Server",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. Adversaries may compromise VPSs purchased by third-party entities. By compromising a VPS to use as infrastructure, adversaries can make it difficult to physically tie back operations to themselves.(Citation: NSA NCSC Turla OilRig)<br /><br />Compromising a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow adversaries to benefit from the ubiquity and trust associated with higher reputation cloud service providers as well as that added by the compromised third-party.<br /><br />",
    "technique_references": [
      {
        "source_name": "NSA NCSC Turla OilRig",
        "url": "https://media.defense.gov/2019/Oct/18/2002197242/-1/-1/0/NSA_CSA_Turla_20191021%20ver%204%20-%20nsa.gov.pdf",
        "description": "NSA/NCSC. (2019, October 21). Cybersecurity Advisory: Turla Group Exploits Iranian APT To Expand Coverage Of Victims. Retrieved October 16, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e196b5c5-8118-4a1c-ab8a-936586ce3db5",
    "platform": "pre",
    "tid": "T1584.004",
    "technique": "Server",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may compromise third-party servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, including for Command and Control. Instead of purchasing a [Server](https://attack.mitre.org/techniques/T1583/004) or [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003), adversaries may compromise third-party servers in support of operations.<br /><br />Adversaries may also compromise web servers to support watering hole operations, as in [Drive-by Compromise](https://attack.mitre.org/techniques/T1189).<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--810d8072-afb6-4a56-9ee7-86379ac4a6f3",
    "platform": "pre",
    "tid": "T1584.005",
    "technique": "Botnet",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may compromise numerous third-party systems to form a botnet that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks.(Citation: Norton Botnet) Instead of purchasing/renting a botnet from a booter/stresser service(Citation: Imperva DDoS for Hire), adversaries may build their own botnet by compromising numerous third-party systems. Adversaries may also conduct a takeover of an existing botnet, such as redirecting bots to adversary-controlled C2 servers.(Citation: Dell Dridex Oct 2015) With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale [Phishing](https://attack.mitre.org/techniques/T1566) or Distributed Denial of Service (DDoS).<br /><br />",
    "technique_references": [
      {
        "source_name": "Norton Botnet",
        "url": "https://us.norton.com/internetsecurity-malware-what-is-a-botnet.html",
        "description": "Norton. (n.d.). What is a botnet?. Retrieved October 4, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Imperva DDoS for Hire",
        "url": "https://www.imperva.com/learn/ddos/booters-stressers-ddosers/",
        "description": "Imperva. (n.d.). Booters, Stressers and DDoSers. Retrieved October 4, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Dell Dridex Oct 2015",
        "url": "https://www.secureworks.com/research/dridex-bugat-v5-botnet-takeover-operation",
        "description": "Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, October 13). Dridex (Bugat v5) Botnet Takeover Operation. Retrieved May 31, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ae797531-3219-49a4-bccf-324ad7a4c7b2",
    "platform": "pre",
    "tid": "T1584.006",
    "technique": "Web Services",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may compromise access to third-party web services that can be used during targeting. A variety of popular websites exist for legitimate users to register for web-based services, such as GitHub, Twitter, Dropbox, Google, etc. Adversaries may try to take ownership of a legitimate user's access to a web service and use that web service as infrastructure in support of cyber operations. Such web services can be abused during later stages of the adversary lifecycle, such as during Command and Control ([Web Service](https://attack.mitre.org/techniques/T1102)) or [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567).(Citation: Recorded Future Turla Infra 2020) Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. By utilizing a web service, particularly when access is stolen from legitimate users, adversaries can make it difficult to physically tie back operations to them.<br /><br />",
    "technique_references": [
      {
        "source_name": "Recorded Future Turla Infra 2020",
        "url": "https://www.recordedfuture.com/turla-apt-infrastructure/",
        "description": "Insikt Group. (2020, March 12). Swallowing the Snake’s Tail: Tracking Turla Infrastructure. Retrieved October 20, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b1ccd744-3f78-4a0e-9bb2-2002057f7928",
    "platform": "pre",
    "tid": "T1585.001",
    "technique": "Social Media Accounts",
    "tactic": "resource-development",
    "datasources": "social-media-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may create and cultivate social media accounts that can be used during targeting. Adversaries can create social media accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage)<br /><br />For operations incorporating social engineering, the utilization of a persona on social media may be important. These personas may be fictitious or impersonate real people. The persona may exist on a single social media site or across multiple sites (ex: Facebook, LinkedIn, Twitter, etc.). Establishing a persona  on social media may require development of additional documentation to make them seem real. This could include filling out profile information, developing social networks, or incorporating photos. <br /><br />Once a persona has been developed an adversary can use it to create connections to targets of interest. These connections may be direct or may include trying to connect through others.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage) These accounts may be leveraged during other phases of the adversary lifecycle, such as during Initial Access (ex: [Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)).<br /><br />",
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
      }
    ]
  },
  {
    "id": "attack-pattern--65013dd2-bc61-43e3-afb5-a14c4fa7437a",
    "platform": "pre",
    "tid": "T1585.002",
    "technique": "Email Accounts",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may create email accounts that can be used during targeting. Adversaries can use accounts created with email providers to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566).(Citation: Mandiant APT1) Adversaries may also take steps to cultivate a persona around the email account, such as through use of [Social Media Accounts](https://attack.mitre.org/techniques/T1585/001), to increase the chance of success of follow-on behaviors. Created email accounts can also be used in the acquisition of infrastructure (ex: [Domains](https://attack.mitre.org/techniques/T1583/001)).(Citation: Mandiant APT1)<br /><br />To decrease the chance of physically tying back operations to themselves, adversaries may make use of disposable email services.(Citation: Trend Micro R980 2016)<br /><br />",
    "technique_references": [
      {
        "source_name": "Mandiant APT1",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf",
        "description": "Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Trend Micro R980 2016",
        "url": "https://blog.trendmicro.com/trendlabs-security-intelligence/r980-ransomware-disposable-email-service/",
        "description": "Antazo, F. and Yambao, M. (2016, August 10). R980 Ransomware Found Abusing Disposable Email Address Service. Retrieved October 13, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--274770e0-2612-4ccf-a678-ef8e7bad365d",
    "platform": "pre",
    "tid": "T1586.001",
    "technique": "Social Media Accounts",
    "tactic": "resource-development",
    "datasources": "social-media-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may compromise social media accounts that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating social media profiles (i.e. [Social Media Accounts](https://attack.mitre.org/techniques/T1585/001)), adversaries may compromise existing social media accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. <br /><br />A variety of methods exist for compromising social media accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, or by brute forcing credentials (ex: password reuse from breach credential dumps).(Citation: AnonHBGary) Prior to compromising social media accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation.<br /><br />Personas may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, etc.). Compromised social media accounts may require additional development, this could include filling out or modifying profile information, further developing social networks, or incorporating photos.<br /><br />Adversaries can use a compromised social media profile to create new, or hijack existing, connections to targets of interest. These connections may be direct or may include trying to connect through others.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage) Compromised profiles may be leveraged during other phases of the adversary lifecycle, such as during Initial Access (ex: [Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)).<br /><br />",
    "technique_references": [
      {
        "source_name": "AnonHBGary",
        "url": "https://arstechnica.com/tech-policy/2011/02/anonymous-speaks-the-inside-story-of-the-hbgary-hack/",
        "description": "Bright, P. (2011, February 15). Anonymous speaks: the inside story of the HBGary hack. Retrieved March 9, 2017.",
        "external_id": "none"
      },
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
      }
    ]
  },
  {
    "id": "attack-pattern--3dc8c101-d4db-4f4d-8150-1b5a76ca5f1b",
    "platform": "pre",
    "tid": "T1586.002",
    "technique": "Email Accounts",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may compromise email accounts that can be used during targeting. Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566). Utilizing an existing persona with a compromised email account may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. Compromised email accounts can also be used in the acquisition of infrastructure (ex: [Domains](https://attack.mitre.org/techniques/T1583/001)).<br /><br />A variety of methods exist for compromising email accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, or by brute forcing credentials (ex: password reuse from breach credential dumps).(Citation: AnonHBGary) Prior to compromising email accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation.<br /><br />Adversaries can use a compromised email account to hijack existing email threads with targets of interest.<br /><br />",
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
    "id": "attack-pattern--212306d8-efa4-44c9-8c2d-ed3d2e224aa0",
    "platform": "pre",
    "tid": "T1587.001",
    "technique": "Malware",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may develop malware and malware components that can be used during targeting. Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors, packers, C2 protocols, and the creation of infected removable media. Adversaries may develop malware to support their operations, creating a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.(Citation: Mandiant APT1)(Citation: Kaspersky Sofacy)(Citation: ActiveMalwareEnergy)(Citation: FBI Flash FIN7 USB)<br /><br />As with legitimate development efforts, different skill sets may be required for developing malware. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's malware development capabilities, provided the adversary plays a role in shaping requirements and maintains a degree of exclusivity to the malware.<br /><br />Some aspects of malware development, such as C2 protocol development, may require adversaries to obtain additional infrastructure. For example, malware developed that will communicate with Twitter for C2, may require use of [Web Services](https://attack.mitre.org/techniques/T1583/006).(Citation: FireEye APT29)<br /><br />",
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
        "source_name": "ActiveMalwareEnergy",
        "url": "https://arstechnica.com/information-technology/2014/06/active-malware-operation-let-attackers-sabotage-us-energy-industry/",
        "description": "Dan Goodin. (2014, June 30). Active malware operation let attackers sabotage US energy industry. Retrieved March 9, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "FBI Flash FIN7 USB",
        "url": "https://www.losangeles.va.gov/documents/MI-000120-MW.pdf",
        "description": "Federal Bureau of Investigation, Cyber Division. (2020, March 26). FIN7 Cyber Actors Targeting US Businesses Through USB Keystroke Injection Attacks. Retrieved October 14, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye APT29",
        "url": "https://www2.fireeye.com/rs/848-DID-242/images/rpt-apt29-hammertoss.pdf",
        "description": "FireEye Labs. (2015, July). HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group. Retrieved September 17, 2015.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--34b3f738-bd64-40e5-a112-29b0542bc8bf",
    "platform": "pre",
    "tid": "T1587.002",
    "technique": "Code Signing Certificates",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may create self-signed code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with.(Citation: Wikipedia Code Signing) Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.<br /><br />Prior to [Code Signing](https://attack.mitre.org/techniques/T1553/002), adversaries may develop self-signed code signing certificates for use in operations.<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia Code Signing",
        "url": "https://en.wikipedia.org/wiki/Code_signing",
        "description": "Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1cec9319-743b-4840-bb65-431547bce82a",
    "platform": "pre",
    "tid": "T1587.003",
    "technique": "Digital Certificates",
    "tactic": "resource-development",
    "datasources": "ssl-tls-certificates",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may create self-signed SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner. In the case of self-signing, digital certificates will lack the element of trust associated with the signature of a third-party certificate authority (CA).<br /><br />Adversaries may create self-signed SSL/TLS certificates that can be used to further their operations, such as encrypting C2 traffic (ex: [Web Protocols](https://attack.mitre.org/techniques/T1071/001)) or even enabling [Man-in-the-Middle](https://attack.mitre.org/techniques/T1557) if added to the root of trust (i.e. [Install Root Certificate](https://attack.mitre.org/techniques/T1553/004)).<br /><br />",
    "technique_references": [
      {
        "source_name": "Splunk Kovar Certificates 2017",
        "url": "https://www.splunk.com/en_us/blog/security/tall-tales-of-hunting-with-tls-ssl-certificates.html",
        "description": "Kovar, R. (2017, December 11). Tall Tales of Hunting with TLS/SSL Certificates. Retrieved October 16, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--bbc3cba7-84ae-410d-b18b-16750731dfa2",
    "platform": "pre",
    "tid": "T1587.004",
    "technique": "Exploits",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may develop exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than finding/modifying exploits from online or purchasing them from exploit vendors, an adversary may develop their own exploits.(Citation: NYTStuxnet) Adversaries may use information acquired via [Vulnerabilities](https://attack.mitre.org/techniques/T1588/006) to focus exploit development efforts. As part of the exploit development process, adversaries may uncover exploitable vulnerabilities through methods such as fuzzing and patch analysis.(Citation: Irongeek Sims BSides 2017)<br /><br />As with legitimate development efforts, different skill sets may be required for developing exploits. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's exploit development capabilities, provided the adversary plays a role in shaping requirements and maintains an initial degree of exclusivity to the exploit.<br /><br />Adversaries may use exploits during various phases of the adversary lifecycle (i.e. [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068), [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211), [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212), [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210), and [Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004)).<br /><br />",
    "technique_references": [
      {
        "source_name": "NYTStuxnet",
        "url": "https://www.nytimes.com/2011/01/16/world/middleeast/16stuxnet.html",
        "description": "William J. Broad, John Markoff, and David E. Sanger. (2011, January 15). Israeli Test on Worm Called Crucial in Iran Nuclear Delay. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Irongeek Sims BSides 2017",
        "url": "https://www.irongeek.com/i.php?page=videos/bsidescharm2017/bsidescharm-2017-t111-microsoft-patch-analysis-for-exploitation-stephen-sims",
        "description": "Stephen Sims. (2017, April 30). Microsoft Patch Analysis for Exploitation. Retrieved October 16, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7807d3a4-a885-4639-a786-c1ed41484970",
    "platform": "pre",
    "tid": "T1588.001",
    "technique": "Malware",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may buy, steal, or download malware that can be used during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, packers, and C2 protocols. Adversaries may acquire malware to support their operations, obtaining a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.<br /><br />In addition to downloading free malware from the internet, adversaries may purchase these capabilities from third-party entities. Third-party entities can include technology companies that specialize in malware development, criminal marketplaces (including Malware-as-a-Service, or MaaS), or from individuals. In addition to purchasing malware, adversaries may steal and repurpose malware from third-party entities (including other adversaries).<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--a2fdce72-04b2-409a-ac10-cc1695f4fce0",
    "platform": "pre",
    "tid": "T1588.002",
    "technique": "Tool",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may buy, steal, or download software tools that can be used during targeting. Tools can be open or closed source, free or commercial. A tool can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: [PsExec](https://attack.mitre.org/software/S0029)). Tool acquisition can involve the procurement of commercial software licenses, including for red teaming tools such as [Cobalt Strike](https://attack.mitre.org/software/S0154). Commercial software may be obtained through purchase, stealing licenses (or licensed copies of the software), or cracking trial versions.(Citation: Recorded Future Beacon 2019)<br /><br />Adversaries may obtain tools to support their operations, including to support execution of post-compromise behaviors. In addition to freely downloading or purchasing software, adversaries may steal software and/or software licenses from third-party entities (including other adversaries).<br /><br />",
    "technique_references": [
      {
        "source_name": "Recorded Future Beacon 2019",
        "url": "https://www.recordedfuture.com/identifying-cobalt-strike-servers/",
        "description": "Recorded Future. (2019, June 20). Out of the Blue: How Recorded Future Identified Rogue Cobalt Strike Servers. Retrieved October 16, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e7cbc1de-1f79-48ee-abfd-da1241c65a15",
    "platform": "pre",
    "tid": "T1588.003",
    "technique": "Code Signing Certificates",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may buy and/or steal code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with.(Citation: Wikipedia Code Signing) Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.<br /><br />Prior to [Code Signing](https://attack.mitre.org/techniques/T1553/002), adversaries may purchase or steal code signing certificates for use in operations. The purchase of code signing certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal code signing materials directly from a compromised third-party.<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia Code Signing",
        "url": "https://en.wikipedia.org/wiki/Code_signing",
        "description": "Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--19401639-28d0-4c3c-adcc-bc2ba22f6421",
    "platform": "pre",
    "tid": "T1588.004",
    "technique": "Digital Certificates",
    "tactic": "resource-development",
    "datasources": "ssl-tls-certificates",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Before compromising a victim, adversaries may buy and/or steal SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner.<br /><br />Adversaries may purchase or steal SSL/TLS certificates to further their operations, such as encrypting C2 traffic (ex: [Web Protocols](https://attack.mitre.org/techniques/T1071/001)) or even enabling [Man-in-the-Middle](https://attack.mitre.org/techniques/T1557) if the certificate is trusted or otherwise added to the root of trust (i.e. [Install Root Certificate](https://attack.mitre.org/techniques/T1553/004)). The purchase of digital certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal certificate materials directly from a compromised third-party, including from certificate authorities.(Citation: DiginotarCompromise)<br /><br />Certificate authorities exist that allow adversaries to acquire SSL/TLS certificates, such as domain validation certificates, for free.(Citation: Let's Encrypt FAQ)<br /><br />Adversaries may register or hijack domains that they will later purchase an SSL/TLS certificate for.<br /><br />",
    "technique_references": [
      {
        "source_name": "DiginotarCompromise",
        "url": "https://threatpost.com/final-report-diginotar-hack-shows-total-compromise-ca-servers-103112/77170/",
        "description": "Fisher, D. (2012, October 31). Final Report on DigiNotar Hack Shows Total Compromise of CA Servers. Retrieved March 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Let's Encrypt FAQ",
        "url": "https://letsencrypt.org/docs/faq/",
        "description": "Let's Encrypt. (2020, April 23). Let's Encrypt FAQ. Retrieved October 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Splunk Kovar Certificates 2017",
        "url": "https://www.splunk.com/en_us/blog/security/tall-tales-of-hunting-with-tls-ssl-certificates.html",
        "description": "Kovar, R. (2017, December 11). Tall Tales of Hunting with TLS/SSL Certificates. Retrieved October 16, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Recorded Future Beacon Certificates",
        "url": "https://www.recordedfuture.com/cobalt-strike-servers/",
        "description": "Insikt Group. (2019, June 18). A Multi-Method Approach to Identifying Rogue Cobalt Strike Servers. Retrieved October 16, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f4b843c1-7e92-4701-8fed-ce82f8be2636",
    "platform": "pre",
    "tid": "T1588.005",
    "technique": "Exploits",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may buy, steal, or download exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than developing their own exploits, an adversary may find/modify exploits from online or purchase them from exploit vendors.(Citation: Exploit Database)(Citation: TempertonDarkHotel)(Citation: NationsBuying)<br /><br />In addition to downloading free exploits from the internet, adversaries may purchase exploits from third-party entities. Third-party entities can include technology companies that specialize in exploit development, criminal marketplaces (including exploit kits), or from individuals.(Citation: PegasusCitizenLab)(Citation: Wired SandCat Oct 2019) In addition to purchasing exploits, adversaries may steal and repurpose exploits from third-party entities (including other adversaries).(Citation: TempertonDarkHotel)<br /><br />An adversary may monitor exploit provider forums to understand the state of existing, as well as newly discovered, exploits. There is usually a delay between when an exploit is discovered and when it is made public. An adversary may target the systems of those known to conduct exploit research and development in order to gain that knowledge for use during a subsequent operation.<br /><br />Adversaries may use exploits during various phases of the adversary lifecycle (i.e. [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068), [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211), [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212), [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210), and [Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004)).<br /><br />",
    "technique_references": [
      {
        "source_name": "Exploit Database",
        "url": "https://www.exploit-db.com/",
        "description": "Offensive Security. (n.d.). Exploit Database. Retrieved October 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "TempertonDarkHotel",
        "url": "https://www.wired.co.uk/article/darkhotel-hacking-team-cyber-espionage",
        "description": "Temperton, J. (2015, August 10). Hacking Team zero-day used in new Darkhotel attacks. Retrieved March 9, 2017.",
        "external_id": "none"
      },
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
        "source_name": "Wired SandCat Oct 2019",
        "url": "https://www.vice.com/en/article/3kx5y3/uzbekistan-hacking-operations-uncovered-due-to-spectacularly-bad-opsec",
        "description": "Zetter, K. (2019, October 3). Researchers Say They Uncovered Uzbekistan Hacking Operations Due to Spectacularly Bad OPSEC. Retrieved October 15, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--2b5aa86b-a0df-4382-848d-30abea443327",
    "platform": "pre",
    "tid": "T1588.006",
    "technique": "Vulnerabilities",
    "tactic": "resource-development",
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
    "technique_description": "Before compromising a victim, adversaries may acquire information about vulnerabilities that can be used during targeting. A vulnerability is a weakness in computer hardware or software that can, potentially, be exploited by an adversary to cause unintended or unanticipated behavior to occur. Adversaries may find vulnerability information by searching open databases or gaining access to closed vulnerability databases.(Citation: National Vulnerability Database)<br /><br />An adversary may monitor vulnerability disclosures/databases to understand the state of existing, as well as newly discovered, vulnerabilities. There is usually a delay between when a vulnerability is discovered and when it is made public. An adversary may target the systems of those known to conduct vulnerability research (including commercial vendors). Knowledge of a vulnerability may cause an adversary to search for an existing exploit (i.e. [Exploits](https://attack.mitre.org/techniques/T1588/005)) or to attempt to develop one themselves (i.e. [Exploits](https://attack.mitre.org/techniques/T1587/004)).<br /><br />",
    "technique_references": [
      {
        "source_name": "National Vulnerability Database",
        "url": "https://nvd.nist.gov/",
        "description": "National Vulnerability Database. (n.d.). National Vulnerability Database. Retrieved October 15, 2020.",
        "external_id": "none"
      }
    ]
  }
]
