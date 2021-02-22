 [
  {
    "id": "attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22",
    "platform": "windows|linux|macos",
    "tid": "T1003",
    "technique": "OS Credential Dumping",
    "tactic": "credential-access",
    "datasources": "api-monitoring|powershell-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1003.001",
      "T1003.002",
      "T1003.003",
      "T1003.004",
      "T1003.005",
      "T1003.006",
      "T1003.007",
      "T1003.008"
    ],
    "count_subtechniques": 8,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.<br /><br />Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.<br /><br />",
    "technique_references": [
      {
        "source_name": "Medium Detecting Attempts to Steal Passwords from Memory",
        "url": "https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea",
        "description": "French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Powersploit",
        "url": "https://github.com/mattifestation/PowerSploit",
        "description": "PowerSploit. (n.d.). Retrieved December 4, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft DRSR Dec 2017",
        "url": "https://msdn.microsoft.com/library/cc228086.aspx",
        "description": "Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft GetNCCChanges",
        "url": "https://msdn.microsoft.com/library/dd207691.aspx",
        "description": "Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Samba DRSUAPI",
        "url": "https://wiki.samba.org/index.php/DRSUAPI",
        "description": "SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Harmj0y DCSync Sept 2015",
        "url": "http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/",
        "description": "Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft NRPC Dec 2017",
        "url": "https://msdn.microsoft.com/library/cc237008.aspx",
        "description": "Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SAMR",
        "url": "https://msdn.microsoft.com/library/cc245496.aspx",
        "description": "Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "AdSecurity DCSync Sept 2015",
        "url": "https://adsecurity.org/?p=1729",
        "description": "Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3257eb21-f9a7-4430-8de1-d8b6e288f529",
    "platform": "linux|macos|windows",
    "tid": "T1040",
    "technique": "Network Sniffing",
    "tactic": "credential-access",
    "datasources": "host-network-interface|netflow-enclave-netflow|network-device-logs|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.<br /><br />Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.<br /><br />Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/158.html",
        "description": "none",
        "external_id": "CAPEC-158"
      }
    ]
  },
  {
    "id": "attack-pattern--bb5a00de-e086-4859-a231-fa793f6797e2",
    "platform": "linux|macos|windows|network",
    "tid": "T1056",
    "technique": "Input Capture",
    "tactic": "credential-access",
    "datasources": "api-monitoring|binary-file-metadata|dll-monitoring|kernel-drivers|loaded-dlls|powershell-logs|process-command-line-parameters|process-monitoring|user-interface|windows-event-logs|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1056.001",
      "T1056.002",
      "T1056.003",
      "T1056.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004)) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. [Web Portal Capture](https://attack.mitre.org/techniques/T1056/003)).<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/569.html",
        "description": "none",
        "external_id": "CAPEC-569"
      },
      {
        "source_name": "Adventures of a Keystroke",
        "url": "http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf",
        "description": "Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd",
    "platform": "linux|macos|windows|office-365|azure-ad|saas|gcp|aws|azure",
    "tid": "T1110",
    "technique": "Brute Force",
    "tactic": "credential-access",
    "datasources": "authentication-logs|office-365-account-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1110.001",
      "T1110.002",
      "T1110.003",
      "T1110.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/49.html",
        "description": "none",
        "external_id": "CAPEC-49"
      }
    ]
  },
  {
    "id": "attack-pattern--dd43c543-bb85-4a6f-aa6e-160d90d06a49",
    "platform": "linux|windows|macos",
    "tid": "T1111",
    "technique": "Two-Factor Authentication Interception",
    "tactic": "credential-access",
    "datasources": "api-monitoring|kernel-drivers|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may target two-factor authentication mechanisms, such as smart cards, to gain access to credentials that can be used to access systems, services, and network resources. Use of two or multi-factor authentication (2FA or MFA) is recommended and provides a higher level of security than user names and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. <br /><br />If a smart card is used for two-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token. (Citation: Mandiant M Trends 2011)<br /><br />Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID. Capturing token input (including a user's personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes). (Citation: GCN RSA June 2011)<br /><br />Other methods of 2FA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Although primarily focused on by cyber criminals, these authentication mechanisms have been targeted by advanced actors. (Citation: Operation Emmental)<br /><br />",
    "technique_references": [
      {
        "source_name": "Mandiant M Trends 2011",
        "url": "https://dl.mandiant.com/EE/assets/PDF_MTrends_2011.pdf",
        "description": "Mandiant. (2011, January 27). Mandiant M-Trends 2011. Retrieved January 10, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "GCN RSA June 2011",
        "url": "https://gcn.com/articles/2011/06/07/rsa-confirms-tokens-used-to-hack-lockheed.aspx",
        "description": "Jackson, William. (2011, June 7). RSA confirms its tokens used in Lockheed hack. Retrieved September 24, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Operation Emmental",
        "url": "http://www.trendmicro.com/cloud-content/us/pdfs/security-intelligence/white-papers/wp-finding-holes-operation-emmental.pdf",
        "description": "Sancho, D., Hacquebord, F., Link, R. (2014, July 22). Finding Holes Operation Emmental. Retrieved February 9, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b77cf5f3-6060-475d-bd60-40ccbf28fdc2",
    "platform": "windows",
    "tid": "T1187",
    "technique": "Forced Authentication",
    "tactic": "credential-access",
    "datasources": "file-monitoring|network-device-logs|network-protocol-analysis|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.<br /><br />The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing. When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system. (Citation: Wikipedia Server Message Block) This behavior is typical in enterprise environments so that users do not need to enter credentials to access network resources.<br /><br />Web Distributed Authoring and Versioning (WebDAV) is also typically used by Windows systems as a backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443. (Citation: Didier Stevens WebDAV Traffic) (Citation: Microsoft Managing WebDAV Security)<br /><br />Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication. An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary (i.e. [Template Injection](https://attack.mitre.org/techniques/T1221)), or place a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed on desktop) or on a publicly accessible share to be accessed by victim(s). When the user's system accesses the untrusted resource it will attempt authentication and send information, including the user's hashed credentials, over SMB to the adversary controlled server. (Citation: GitHub Hashjacking) With access to the credential hash, an adversary can perform off-line [Brute Force](https://attack.mitre.org/techniques/T1110) cracking to gain access to plaintext credentials. (Citation: Cylance Redirect to SMB)<br /><br />There are several different ways this can occur. (Citation: Osanda Stealing NetNTLM Hashes) Some specifics from in-the-wild use include:<br /><br />* A spearphishing attachment containing a document with a resource that is automatically loaded when the document is opened (i.e. [Template Injection](https://attack.mitre.org/techniques/T1221)). The document can include, for example, a request similar to <code>file[:]//[remote address]/Normal.dotm</code> to trigger the SMB request. (Citation: US-CERT APT Energy Oct 2017)<br /><br />* A modified .LNK or .SCF file with the icon filename pointing to an external reference such as <code>\\\\[remote address]\\pic.png</code> that will force the system to load the resource when the icon is rendered to repeatedly gather credentials. (Citation: US-CERT APT Energy Oct 2017)<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia Server Message Block",
        "url": "https://en.wikipedia.org/wiki/Server_Message_Block",
        "description": "Wikipedia. (2017, December 16). Server Message Block. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Didier Stevens WebDAV Traffic",
        "url": "https://blog.didierstevens.com/2017/11/13/webdav-traffic-to-malicious-sites/",
        "description": "Stevens, D. (2017, November 13). WebDAV Traffic To Malicious Sites. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Managing WebDAV Security",
        "url": "https://www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/4beddb35-0cba-424c-8b9b-a5832ad8e208.mspx",
        "description": "Microsoft. (n.d.). Managing WebDAV Security (IIS 6.0). Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Hashjacking",
        "url": "https://github.com/hob0/hashjacking",
        "description": "Dunning, J. (2016, August 1). Hashjacking. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Cylance Redirect to SMB",
        "url": "https://www.cylance.com/content/dam/cylance/pdfs/white_papers/RedirectToSMB.pdf",
        "description": "Cylance. (2015, April 13). Redirect to SMB. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Osanda Stealing NetNTLM Hashes",
        "url": "https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/",
        "description": "Osanda Malith Jayathissa. (2017, March 24). Places of Interest in Stealing NetNTLM Hashes. Retrieved January 26, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "US-CERT APT Energy Oct 2017",
        "url": "https://www.us-cert.gov/ncas/alerts/TA17-293A",
        "description": "US-CERT. (2017, October 20). Alert (TA17-293A): Advanced Persistent Threat Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved November 2, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--9c306d8d-cde7-4b4c-b6e8-d0bb16caca36",
    "platform": "linux|windows|macos",
    "tid": "T1212",
    "technique": "Exploitation for Credential Access",
    "tactic": "credential-access",
    "datasources": "authentication-logs|process-monitoring|windows-error-reporting",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain access to systems. One example of this is MS14-068, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions.(Citation: Technet MS14-068)(Citation: ADSecurity Detecting Forged Tickets) Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained.<br /><br />",
    "technique_references": [
      {
        "source_name": "Technet MS14-068",
        "url": "https://technet.microsoft.com/en-us/library/security/ms14-068.aspx",
        "description": "Microsoft. (2014, November 18). Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780). Retrieved December 23, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "ADSecurity Detecting Forged Tickets",
        "url": "https://adsecurity.org/?p=1515",
        "description": "Metcalf, S. (2015, May 03). Detecting Forged Kerberos Ticket (Golden Ticket & Silver Ticket) Use in Active Directory. Retrieved December 23, 2015.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--890c9858-598c-401d-a4d5-c67ebcdd703a",
    "platform": "saas|office-365|azure-ad",
    "tid": "T1528",
    "technique": "Steal Application Access Token",
    "tactic": "credential-access",
    "datasources": "azure-activity-logs|oauth-audit-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries can steal user application access tokens as a means of acquiring credentials to access remote systems and resources. This can occur through social engineering and typically requires user action to grant access.<br /><br />Application access tokens are used to make authorized API requests on behalf of a user and are commonly used as a way to access resources in cloud-based applications and software-as-a-service (SaaS).(Citation: Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019) OAuth is one commonly implemented framework that issues tokens to users for access to systems. An application desiring access to cloud-based services or protected APIs can gain entry using OAuth 2.0 through a variety of authorization protocols. An example commonly-used sequence is Microsoft's Authorization Code Grant flow.(Citation: Microsoft Identity Platform Protocols May 2019)(Citation: Microsoft - OAuth Code Authorization flow - June 2019) An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested by the application without obtaining user credentials. <br /><br /> <br /><br />Adversaries can leverage OAuth authorization by constructing a malicious application designed to be granted access to resources with the target user's OAuth token. The adversary will need to complete registration of their application with the authorization server, for example Microsoft Identity Platform using Azure Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST API calls.(Citation: Microsoft - Azure AD App Registration - May 2019) Then, they can send a link through [Spearphishing Link](https://attack.mitre.org/techniques/T1192) to the target user to entice them to grant access to the application. Once the OAuth access token is granted, the application can gain potentially long-term access to features of the user account through [Application Access Token](https://attack.mitre.org/techniques/T1527).(Citation: Microsoft - Azure AD Identity Tokens - Aug 2019)<br /><br />Adversaries have been seen targeting Gmail, Microsoft Outlook, and Yahoo Mail users.(Citation: Amnesty OAuth Phishing Attacks, August 2019)(Citation: Trend Micro Pawn Storm OAuth 2017)<br /><br />",
    "technique_references": [
      {
        "source_name": "Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019",
        "url": "https://auth0.com/blog/why-should-use-accesstokens-to-secure-an-api/",
        "description": "Auth0. (n.d.). Why You Should Always Use Access Tokens to Secure APIs. Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Identity Platform Protocols May 2019",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols",
        "description": "Microsoft. (n.d.). Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - OAuth Code Authorization flow - June 2019",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow",
        "description": "Microsoft. (n.d.). Microsoft identity platform and OAuth 2.0 authorization code flow. Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Azure AD App Registration - May 2019",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app",
        "description": "Microsoft. (2019, May 8). Quickstart: Register an application with the Microsoft identity platform. Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Azure AD Identity Tokens - Aug 2019",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens",
        "description": "Microsoft. (2019, August 29). Microsoft identity platform access tokens. Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Amnesty OAuth Phishing Attacks, August 2019",
        "url": "https://www.amnesty.org/en/latest/research/2019/08/evolving-phishing-attacks-targeting-journalists-and-human-rights-defenders-from-the-middle-east-and-north-africa/",
        "description": "Amnesty International. (2019, August 16). Evolving Phishing Attacks Targeting Journalists and Human Rights Defenders from the Middle-East and North Africa. Retrieved October 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Trend Micro Pawn Storm OAuth 2017",
        "url": "https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks",
        "description": "Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--10ffac09-e42d-4f56-ab20-db94c67d76ff",
    "platform": "linux|macos|windows|office-365|saas",
    "tid": "T1539",
    "technique": "Steal Web Session Cookie",
    "tactic": "credential-access",
    "datasources": "api-monitoring|file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may steal web application or service session cookies and use them to gain access web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website.<br /><br />Cookies are often valid for an extended period of time, even if the web application is not actively used. Cookies can be found on disk, in the process memory of the browser, and in network traffic to remote systems. Additionally, other applications on the targets machine might store sensitive authentication cookies in memory (e.g. apps which authenticate to cloud services). Session cookies can be used to bypasses some multi-factor authentication protocols.(Citation: Pass The Cookie)<br /><br />There are several examples of malware targeting cookies from web browsers on the local system.(Citation: Kaspersky TajMahal April 2019)(Citation: Unit 42 Mac Crypto Cookies January 2019) There are also open source frameworks such as Evilginx 2 and Muraena that can gather session cookies through a man-in-the-middle proxy that can be set up by an adversary and used in phishing campaigns.(Citation: Github evilginx2)(Citation: GitHub Mauraena)<br /><br />After an adversary acquires a valid cookie, they can then perform a [Web Session Cookie](https://attack.mitre.org/techniques/T1506) technique to login to the corresponding web application.<br /><br />",
    "technique_references": [
      {
        "source_name": "Pass The Cookie",
        "url": "https://wunderwuzzi23.github.io/blog/passthecookie.html",
        "description": "Rehberger, J. (2018, December). Pivot to the Cloud using Pass the Cookie. Retrieved April 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Kaspersky TajMahal April 2019",
        "url": "https://securelist.com/project-tajmahal/90240/",
        "description": "GReAT. (2019, April 10). Project TajMahal – a sophisticated new APT framework. Retrieved October 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Unit 42 Mac Crypto Cookies January 2019",
        "url": "https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/",
        "description": "Chen, Y., Hu, W., Xu, Z., et. al.. (2019, January 31). Mac Malware Steals Cryptocurrency Exchanges’ Cookies. Retrieved October 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Github evilginx2",
        "url": "https://github.com/kgretzky/evilginx2",
        "description": "Gretzky, Kuba. (2019, April 10). Retrieved October 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Mauraena",
        "url": "https://github.com/muraenateam/muraena",
        "description": "Orrù, M., Trotta, G.. (2019, September 11). Muraena. Retrieved October 14, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--435dfb86-2697-4867-85b5-2fef496c0517",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1552",
    "technique": "Unsecured Credentials",
    "tactic": "credential-access",
    "datasources": "authentication-logs|aws-cloudtrail-logs|azure-activity-logs|file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1552.001",
      "T1552.002",
      "T1552.003",
      "T1552.004",
      "T1552.005",
      "T1552.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Bash History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)), or other specialized files/artifacts (e.g. [Private Keys](https://attack.mitre.org/techniques/T1552/004)).<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--3fc9b85a-2862-4363-a64d-d692e3ffbee0",
    "platform": "linux|macos|windows",
    "tid": "T1555",
    "technique": "Credentials from Password Stores",
    "tactic": "credential-access",
    "datasources": "api-monitoring|file-monitoring|powershell-logs|process-monitoring|system-calls",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1555.001",
      "T1555.002",
      "T1555.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
    "platform": "windows|linux|macos|network",
    "tid": "T1556",
    "technique": "Modify Authentication Process",
    "tactic": "credential-access",
    "datasources": "api-monitoring|authentication-logs|dll-monitoring|file-monitoring|process-monitoring|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1556.001",
      "T1556.002",
      "T1556.003",
      "T1556.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows or pluggable authentication modules (PAM) on Unix-based systems, responsible for gathering, storing, and validating credentials. <br /><br />Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. <br /><br />",
    "technique_references": [
      {
        "source_name": "Clymb3r Function Hook Passwords Sept 2013",
        "url": "https://clymb3r.wordpress.com/2013/09/15/intercepting-password-changes-with-function-hooking/",
        "description": "Bialek, J. (2013, September 15). Intercepting Password Changes With Function Hooking. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Dell Skeleton",
        "url": "https://www.secureworks.com/research/skeleton-key-malware-analysis",
        "description": "Dell SecureWorks. (2015, January 12). Skeleton Key Malware Analysis. Retrieved April 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Audit Policy",
        "url": "https://technet.microsoft.com/en-us/library/dn487457.aspx",
        "description": "Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d",
    "platform": "windows|macos|linux",
    "tid": "T1557",
    "technique": "Man-in-the-Middle",
    "tactic": "credential-access",
    "datasources": "file-monitoring|netflow-enclave-netflow|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1557.001",
      "T1557.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to position themselves between two or more networked devices using a man-in-the-middle (MiTM) technique to support follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002). By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.(Citation: Rapid7 MiTM Basics)<br /><br />Adversaries may leverage the MiTM position to attempt to modify traffic, such as in [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002). Adversaries can also stop traffic from flowing to the appropriate destination, causing denial of service.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/94.html",
        "description": "none",
        "external_id": "CAPEC-94"
      },
      {
        "source_name": "Rapid7 MiTM Basics",
        "url": "https://www.rapid7.com/fundamentals/man-in-the-middle-attacks/",
        "description": "Rapid7. (n.d.). Man-in-the-Middle (MITM) Attacks. Retrieved March 2, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3fc01293-ef5e-41c6-86ce-61f10706b64a",
    "platform": "windows",
    "tid": "T1558",
    "technique": "Steal or Forge Kerberos Tickets",
    "tactic": "credential-access",
    "datasources": "authentication-logs|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1558.001",
      "T1558.002",
      "T1558.003",
      "T1558.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003). <br /><br />Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as “realms”, there are three basic participants: client, service, and Key Distribution Center (KDC).(Citation: ADSecurity Kerberos Ring Decoder) Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting.  Attackers may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/652.html",
        "description": "none",
        "external_id": "CAPEC-652"
      },
      {
        "source_name": "ADSecurity Kerberos Ring Decoder",
        "url": "https://adsecurity.org/?p=227",
        "description": "Sean Metcalf. (2014, September 12). Kerberos, Active Directory’s Secret Decoder Ring. Retrieved February 27, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ADSecurity Detecting Forged Tickets",
        "url": "https://adsecurity.org/?p=1515",
        "description": "Metcalf, S. (2015, May 03). Detecting Forged Kerberos Ticket (Golden Ticket & Silver Ticket) Use in Active Directory. Retrieved December 23, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "Stealthbits Detect PtT 2019",
        "url": "https://blog.stealthbits.com/detect-pass-the-ticket-attacks",
        "description": "Jeff Warren. (2019, February 19). How to Detect Pass-the-Ticket Attacks. Retrieved February 27, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "CERT-EU Golden Ticket Protection",
        "url": "https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf",
        "description": "Abolins, D., Boldea, C., Socha, K., Soria-Machado, M. (2016, April 26). Kerberos Golden Ticket Protection. Retrieved July 13, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Kerberos Golden Ticket",
        "url": "https://gallery.technet.microsoft.com/scriptcenter/Kerberos-Golden-Ticket-b4814285",
        "description": "Microsoft. (2015, March 24). Kerberos Golden Ticket Check (Updated). Retrieved February 27, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Detecting Kerberoasting Feb 2018",
        "url": "https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/",
        "description": "Bani, M. (2018, February 23). Detecting Kerberoasting activity using Azure Security Center. Retrieved March 23, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "AdSecurity Cracking Kerberos Dec 2015",
        "url": "https://adsecurity.org/?p=2293",
        "description": "Metcalf, S. (2015, December 31). Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain. Retrieved March 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Medium Detecting Attempts to Steal Passwords from Memory",
        "url": "https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea",
        "description": "French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--94cb00a4-b295-4d06-aa2b-5653b9c1be9c",
    "platform": "saas|windows|macos|linux|azure-ad|office-365",
    "tid": "T1606",
    "technique": "Forge Web Credentials",
    "tactic": "credential-access",
    "datasources": "authentication-logs|web-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1606.001",
      "T1606.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access.<br /><br />Adversaries may generate these credential materials in order to gain access to web resources. This differs from [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539), [Steal Application Access Token](https://attack.mitre.org/techniques/T1528), and other similar behaviors in that the credentials are new and forged by the adversary, rather than stolen or intercepted from legitimate users. The generation of web credentials often requires secret values, such as passwords, [Private Keys](https://attack.mitre.org/techniques/T1552/004), or other cryptographic seed values.(Citation: GitHub AWS-ADFS-Credential-Generator)<br /><br />Once forged, adversaries may use these web credentials to access resources (ex: [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)), which may bypass multi-factor and other authentication protection mechanisms.(Citation: Pass The Cookie)(Citation: Unit 42 Mac Crypto Cookies January 2019)(Citation: Microsoft SolarWinds Customer Guidance)<br /><br />",
    "technique_references": [
      {
        "source_name": "GitHub AWS-ADFS-Credential-Generator",
        "url": "https://github.com/damianh/aws-adfs-credential-generator",
        "description": "Damian Hickey. (2017, January 28). AWS-ADFS-Credential-Generator. Retrieved December 16, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Pass The Cookie",
        "url": "https://wunderwuzzi23.github.io/blog/passthecookie.html",
        "description": "Rehberger, J. (2018, December). Pivot to the Cloud using Pass the Cookie. Retrieved April 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Unit 42 Mac Crypto Cookies January 2019",
        "url": "https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/",
        "description": "Chen, Y., Hu, W., Xu, Z., et. al. (2019, January 31). Mac Malware Steals Cryptocurrency Exchanges’ Cookies. Retrieved October 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SolarWinds Customer Guidance",
        "url": "https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/",
        "description": "MSRC. (2020, December 13). Customer Guidance on Recent Nation-State Cyber Attacks. Retrieved December 17, 2020.",
        "external_id": "none"
      }
    ]
  }
]
