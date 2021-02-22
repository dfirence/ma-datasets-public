 [
  {
    "id": "attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90",
    "platform": "windows",
    "tid": "T1003.001",
    "technique": "LSASS Memory",
    "tactic": "credential-access",
    "datasources": "powershell-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).<br /><br />As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.<br /><br />For example, on the target host use procdump:<br /><br />* <code>procdump -ma lsass.exe lsass_dump</code><br /><br />Locally, mimikatz can be run using:<br /><br />* <code>sekurlsa::Minidump lsassdump.dmp</code><br /><br />* <code>sekurlsa::logonPasswords</code><br /><br />Windows Security Support Provider (SSP) DLLs are loaded into LSSAS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages</code> and <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)<br /><br />The following SSPs can be used to access credentials:<br /><br />* Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.<br /><br />* Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.(Citation: TechNet Blogs Credential Protection)<br /><br />* Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.<br /><br />* CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services.(Citation: TechNet Blogs Credential Protection)<br /><br />",
    "technique_references": [
      {
        "source_name": "Graeber 2014",
        "url": "http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html",
        "description": "Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Blogs Credential Protection",
        "url": "https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/",
        "description": "Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.",
        "external_id": "none"
      },
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
      }
    ]
  },
  {
    "id": "attack-pattern--1644e709-12d2-41e5-a60f-3470991f5011",
    "platform": "windows",
    "tid": "T1003.002",
    "technique": "Security Account Manager",
    "tactic": "credential-access",
    "datasources": "powershell-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local accounts for the host, typically those found with the <code>net user</code> command. Enumerating the SAM database requires SYSTEM level access.<br /><br />A number of tools can be used to retrieve the SAM file through in-memory techniques:<br /><br />* pwdumpx.exe<br /><br />* [gsecdump](https://attack.mitre.org/software/S0008)<br /><br />* [Mimikatz](https://attack.mitre.org/software/S0002)<br /><br />* secretsdump.py<br /><br />Alternatively, the SAM can be extracted from the Registry with Reg:<br /><br />* <code>reg save HKLM\\sam sam</code><br /><br />* <code>reg save HKLM\\system system</code><br /><br />Creddump7 can then be used to process the SAM database locally to retrieve hashes.(Citation: GitHub Creddump7)<br /><br />Notes: <br /><br />* RID 500 account is the local, built-in administrator.<br /><br />* RID 501 is the guest account.<br /><br />* User accounts start with a RID of 1,000+.<br /><br />",
    "technique_references": [
      {
        "source_name": "GitHub Creddump7",
        "url": "https://github.com/Neohapsis/creddump7",
        "description": "Flathers, R. (2018, February 19). creddump7. Retrieved April 11, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--edf91964-b26e-4b4a-9600-ccacd7d7df24",
    "platform": "windows",
    "tid": "T1003.003",
    "technique": "NTDS",
    "tactic": "credential-access",
    "datasources": "powershell-logs|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in <code>%SystemRoot%\\NTDS\\Ntds.dit</code> of a domain controller.(Citation: Wikipedia Active Directory)<br /><br />In addition to looking NTDS files on active Domain Controllers, attackers may search for backups that contain the same or similar information.(Citation: Metcalf 2015)<br /><br />The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.<br /><br />* Volume Shadow Copy<br /><br />* secretsdump.py<br /><br />* Using the in-built Windows tool, ntdsutil.exe<br /><br />* Invoke-NinjaCopy<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia Active Directory",
        "url": "https://en.wikipedia.org/wiki/Active_Directory",
        "description": "Wikipedia. (2018, March 10). Active Directory. Retrieved April 11, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Metcalf 2015",
        "url": "http://adsecurity.org/?p=1275",
        "description": "Metcalf, S. (2015, January 19). Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest. Retrieved February 3, 2015.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1ecfdab8-7d59-4c98-95d4-dc41970f57fc",
    "platform": "windows",
    "tid": "T1003.004",
    "technique": "LSA Secrets",
    "tactic": "credential-access",
    "datasources": "powershell-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts.(Citation: Passcape LSA Secrets)(Citation: Microsoft AD Admin Tier Model)(Citation: Tilbury Windows Credentials) LSA secrets are stored in the registry at <code>HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets</code>. LSA secrets can also be dumped from memory.(Citation: ired Dumping LSA Secrets)<br /><br />[Reg](https://attack.mitre.org/software/S0075) can be used to extract from the Registry. [Mimikatz](https://attack.mitre.org/software/S0002) can be used to extract secrets from memory.(Citation: ired Dumping LSA Secrets)<br /><br />",
    "technique_references": [
      {
        "source_name": "Passcape LSA Secrets",
        "url": "https://www.passcape.com/index.php?section=docsys&cmd=details&id=23",
        "description": "Passcape. (n.d.). Windows LSA secrets. Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft AD Admin Tier Model",
        "url": "https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material?redirectedfrom=MSDN",
        "description": "Microsoft. (2019, February 14). Active Directory administrative tier model. Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Tilbury Windows Credentials",
        "url": "https://www.first.org/resources/papers/conf2017/Windows-Credentials-Attacks-and-Mitigation-Techniques.pdf",
        "description": "Chad Tilbury. (2017, August 8). 1Windows Credentials: Attack, Mitigation, Defense. Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ired Dumping LSA Secrets",
        "url": "ttps://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsa-secrets",
        "description": "Mantvydas Baranauskas. (2019, November 16). Dumping LSA Secrets. Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Powersploit",
        "url": "https://github.com/mattifestation/PowerSploit",
        "description": "PowerSploit. (n.d.). Retrieved December 4, 2014.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--6add2ab5-2711-4e9d-87c8-7a0be8531530",
    "platform": "windows",
    "tid": "T1003.005",
    "technique": "Cached Domain Credentials",
    "tactic": "credential-access",
    "datasources": "powershell-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.(Citation: Microsoft - Cached Creds)<br /><br />On Windows Vista and newer, the hash format is DCC2 (Domain Cached Credentials version 2) hash, also known as MS-Cache v2 hash.(Citation: PassLib mscache) The number of default cached credentials varies and can be altered per system. This hash does not allow pass-the-hash style attacks, and instead requires [Password Cracking](https://attack.mitre.org/techniques/T1110/002) to recover the plaintext password.(Citation: ired mscache)<br /><br />With SYSTEM access, the tools/utilities such as [Mimikatz](https://attack.mitre.org/software/S0002), [Reg](https://attack.mitre.org/software/S0075), and secretsdump.py can be used to extract the cached credentials.<br /><br />Note: Cached credentials for Windows Vista are derived using PBKDF2.(Citation: PassLib mscache)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft - Cached Creds",
        "url": "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v%3Dws.11)",
        "description": "Microsfot. (2016, August 21). Cached and Stored Credentials Technical Overview. Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "PassLib mscache",
        "url": "https://passlib.readthedocs.io/en/stable/lib/passlib.hash.msdcc2.html",
        "description": "Eli Collins. (2016, November 25). Windows' Domain Cached Credentials v2. Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ired mscache",
        "url": "https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials",
        "description": "Mantvydas Baranauskas. (2019, November 16). Dumping and Cracking mscash - Cached Domain Credentials. Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Powersploit",
        "url": "https://github.com/mattifestation/PowerSploit",
        "description": "PowerSploit. (n.d.). Retrieved December 4, 2014.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f303a39a-6255-4b89-aecc-18c4d8ca7163",
    "platform": "windows",
    "tid": "T1003.006",
    "technique": "DCSync",
    "tactic": "credential-access",
    "datasources": "windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API)(Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a remote domain controller using a technique called DCSync.<br /><br />Members of the Administrators, Domain Admins, and Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data(Citation: ADSecurity Mimikatz DCSync) from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a [Golden Ticket](https://attack.mitre.org/techniques/T1558/001) for use in [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003)(Citation: Harmj0y Mimikatz and DCSync) or change an account's password as noted in [Account Manipulation](https://attack.mitre.org/techniques/T1098).(Citation: InsiderThreat ChangeNTLM July 2017)<br /><br />DCSync functionality has been included in the \"lsadump\" module in [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: GitHub Mimikatz lsadump Module) Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol.(Citation: Microsoft NRPC Dec 2017)<br /><br />",
    "technique_references": [
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
        "source_name": "Wine API samlib.dll",
        "url": "https://source.winehq.org/WineAPI/samlib.html",
        "description": "Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "ADSecurity Mimikatz DCSync",
        "url": "https://adsecurity.org/?p=1729",
        "description": "Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved August 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Harmj0y Mimikatz and DCSync",
        "url": "http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/",
        "description": "Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved August 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "InsiderThreat ChangeNTLM July 2017",
        "url": "https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM",
        "description": "Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Mimikatz lsadump Module",
        "url": "https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump",
        "description": "Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.",
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
      },
      {
        "source_name": "Harmj0y DCSync Sept 2015",
        "url": "http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/",
        "description": "Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3120b9fa-23b8-4500-ae73-09494f607b7d",
    "platform": "linux",
    "tid": "T1003.007",
    "technique": "Proc Filesystem",
    "tactic": "credential-access",
    "datasources": "process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may gather credentials from information stored in the Proc filesystem or <code>/proc</code>. The Proc filesystem on Linux contains a great deal of information regarding the state of the running operating system. Processes running with root privileges can use this facility to scrape live memory of other running programs. If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively.<br /><br />This functionality has been implemented in the MimiPenguin(Citation: MimiPenguin GitHub May 2017), an open source tool inspired by Mimikatz. The tool dumps process memory, then harvests passwords and hashes by looking for text strings and regex patterns for how given applications such as Gnome Keyring, sshd, and Apache use memory to store such authentication artifacts.<br /><br />",
    "technique_references": [
      {
        "source_name": "MimiPenguin GitHub May 2017",
        "url": "https://github.com/huntergregal/mimipenguin",
        "description": "Gregal, H. (2017, May 12). MimiPenguin. Retrieved December 5, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d0b4fcdb-d67d-4ed2-99ce-788b12f8c0f4",
    "platform": "linux",
    "tid": "T1003.008",
    "technique": "/etc/passwd and /etc/shadow",
    "tactic": "credential-access",
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
    "technique_description": "Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking. Most modern Linux operating systems use a combination of <code>/etc/passwd</code> and <code>/etc/shadow</code> to store user account information including password hashes in <code>/etc/shadow</code>. By default, <code>/etc/shadow</code> is only readable by the root user.(Citation: Linux Password and Shadow File Formats)<br /><br />The Linux utility, unshadow, can be used to combine the two files in a format suited for password cracking utilities such as John the Ripper:(Citation: nixCraft - John the Ripper) <code># /usr/bin/unshadow /etc/passwd /etc/shadow > /tmp/crack.password.db</code><br /><br />",
    "technique_references": [
      {
        "source_name": "Linux Password and Shadow File Formats",
        "url": "https://www.tldp.org/LDP/lame/LAME/linux-admin-made-easy/shadow-file-formats.html",
        "description": "The Linux Documentation Project. (n.d.). Linux Password and Shadow File Formats. Retrieved February 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "nixCraft - John the Ripper",
        "url": "https://www.cyberciti.biz/faq/unix-linux-password-cracking-john-the-ripper/",
        "description": "Vivek Gite. (2014, September 17). Linux Password Cracking: Explain unshadow and john Commands (John the Ripper Tool). Retrieved February 19, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--09a60ea3-a8d1-4ae5-976e-5783248b72a4",
    "platform": "windows|macos|linux|network",
    "tid": "T1056.001",
    "technique": "Keylogging",
    "tactic": "credential-access",
    "datasources": "api-monitoring|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured.<br /><br />Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes.(Citation: Adventures of a Keystroke) Some methods include:<br /><br />* Hooking API callbacks used for processing keystrokes. Unlike [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004), this focuses solely on API functions intended for processing keystroke data.<br /><br />* Reading raw keystroke data from the hardware buffer.<br /><br />* Windows Registry modifications.<br /><br />* Custom drivers.<br /><br />* [Modify System Image](https://attack.mitre.org/techniques/T1601) may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions.(Citation: Cisco Blog Legacy Device Attacks) <br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/568.html",
        "description": "none",
        "external_id": "CAPEC-568"
      },
      {
        "source_name": "Adventures of a Keystroke",
        "url": "http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf",
        "description": "Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.",
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
    "id": "attack-pattern--a2029942-0a85-4947-b23c-ca434698171d",
    "platform": "macos|windows",
    "tid": "T1056.002",
    "technique": "GUI Input Capture",
    "tactic": "credential-access",
    "datasources": "powershell-logs|process-command-line-parameters|process-monitoring|user-interface",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002)).<br /><br />Adversaries may mimic this functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite.(Citation: OSX Malware Exploits MacKeeper) This type of prompt can be used to collect credentials via various languages such as AppleScript(Citation: LogRhythm Do You Trust Oct 2014)(Citation: OSX Keydnap malware) and PowerShell(Citation: LogRhythm Do You Trust Oct 2014)(Citation: Enigma Phishing for Credentials Jan 2015). <br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/659.html",
        "description": "none",
        "external_id": "CAPEC-659"
      },
      {
        "source_name": "OSX Malware Exploits MacKeeper",
        "url": "https://baesystemsai.blogspot.com/2015/06/new-mac-os-malware-exploits-mackeeper.html",
        "description": "Sergei Shevchenko. (2015, June 4). New Mac OS Malware Exploits Mackeeper. Retrieved July 3, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "LogRhythm Do You Trust Oct 2014",
        "url": "https://logrhythm.com/blog/do-you-trust-your-computer/",
        "description": "Foss, G. (2014, October 3). Do You Trust Your Computer?. Retrieved December 17, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "OSX Keydnap malware",
        "url": "https://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-hungry-credentials/",
        "description": "Marc-Etienne M.Leveille. (2016, July 6). New OSX/Keydnap malware is hungry for credentials. Retrieved July 3, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Enigma Phishing for Credentials Jan 2015",
        "url": "https://enigma0x3.net/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/",
        "description": "Nelson, M. (2015, January 21). Phishing for Credentials: If you want it, just ask!. Retrieved December 17, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--69e5226d-05dc-4f15-95d7-44f5ed78d06e",
    "platform": "linux|macos|windows",
    "tid": "T1056.003",
    "technique": "Web Portal Capture",
    "tactic": "credential-access",
    "datasources": "file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service.<br /><br />This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through [External Remote Services](https://attack.mitre.org/techniques/T1133) and [Valid Accounts](https://attack.mitre.org/techniques/T1078) or as part of the initial compromise by exploitation of the externally facing web service.(Citation: Volexity Virtual Private Keylogging)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/569.html",
        "description": "none",
        "external_id": "CAPEC-569"
      },
      {
        "source_name": "Volexity Virtual Private Keylogging",
        "url": "https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/",
        "description": "Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f5946b5e-9408-485f-a7f7-b5efc88909b6",
    "platform": "windows",
    "tid": "T1056.004",
    "technique": "Credential API Hooking",
    "tactic": "credential-access",
    "datasources": "api-monitoring|binary-file-metadata|dll-monitoring|loaded-dlls|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may hook into Windows application programming interface (API) functions to collect user credentials. Malicious hooking mechanisms may capture API calls that include parameters that reveal user authentication credentials.(Citation: Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017) Unlike [Keylogging](https://attack.mitre.org/techniques/T1056/001),  this technique focuses specifically on API functions that include parameters that reveal user credentials. Hooking involves redirecting calls to these functions and can be implemented via:<br /><br />* **Hooks procedures**, which intercept and execute designated code in response to events such as messages, keystrokes, and mouse inputs.(Citation: Microsoft Hook Overview)(Citation: Endgame Process Injection July 2017)<br /><br />* **Import address table (IAT) hooking**, which use modifications to a process’s IAT, where pointers to imported API functions are stored.(Citation: Endgame Process Injection July 2017)(Citation: Adlice Software IAT Hooks Oct 2014)(Citation: MWRInfoSecurity Dynamic Hooking 2015)<br /><br />* **Inline hooking**, which overwrites the first bytes in an API function to redirect code flow.(Citation: Endgame Process Injection July 2017)(Citation: HighTech Bridge Inline Hooking Sept 2011)(Citation: MWRInfoSecurity Dynamic Hooking 2015)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017",
        "url": "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=TrojanSpy:Win32/Ursnif.gen!I&threatId=-2147336918",
        "description": "Microsoft. (2017, September 15). TrojanSpy:Win32/Ursnif.gen!I. Retrieved December 18, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Hook Overview",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms644959.aspx",
        "description": "Microsoft. (n.d.). Hooks Overview. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Adlice Software IAT Hooks Oct 2014",
        "url": "https://www.adlice.com/userland-rootkits-part-1-iat-hooks/",
        "description": "Tigzy. (2014, October 15). Userland Rootkits: Part 1, IAT hooks. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "MWRInfoSecurity Dynamic Hooking 2015",
        "url": "https://www.mwrinfosecurity.com/our-thinking/dynamic-hooking-techniques-user-mode/",
        "description": "Hillman, M. (2015, August 8). Dynamic Hooking Techniques: User Mode. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "HighTech Bridge Inline Hooking Sept 2011",
        "url": "https://www.exploit-db.com/docs/17802.pdf",
        "description": "Mariani, B. (2011, September 6). Inline Hooking in Windows. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Volatility Detecting Hooks Sept 2012",
        "url": "https://volatility-labs.blogspot.com/2012/09/movp-31-detecting-malware-hooks-in.html",
        "description": "Volatility Labs. (2012, September 24). MoVP 3.1 Detecting Malware Hooks in the Windows GUI Subsystem. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "PreKageo Winhook Jul 2011",
        "url": "https://github.com/prekageo/winhook",
        "description": "Prekas, G. (2011, July 11). Winhook. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Jay GetHooks Sept 2011",
        "url": "https://github.com/jay/gethooks",
        "description": "Satiro, J. (2011, September 14). GetHooks. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Zairon Hooking Dec 2006",
        "url": "https://zairon.wordpress.com/2006/12/06/any-application-defined-hook-procedure-on-my-machine/",
        "description": "Felici, M. (2006, December 6). Any application-defined hook procedure on my machine?. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "EyeofRa Detecting Hooking June 2017",
        "url": "https://eyeofrablog.wordpress.com/2017/06/27/windows-keylogger-part-2-defense-against-user-land/",
        "description": "Eye of Ra. (2017, June 27). Windows Keylogger Part 2: Defense against user-land. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GMER Rootkits",
        "url": "http://www.gmer.net/",
        "description": "GMER. (n.d.). GMER. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Process Snapshot",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms686701.aspx",
        "description": "Microsoft. (n.d.). Taking a Snapshot and Viewing Processes. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "StackExchange Hooks Jul 2012",
        "url": "https://security.stackexchange.com/questions/17904/what-are-the-methods-to-find-hooked-functions-and-apis",
        "description": "Stack Exchange - Security. (2012, July 31). What are the methods to find hooked functions and APIs?. Retrieved December 12, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--09c4c11e-4fa1-4f8c-8dad-3cf8e69ad119",
    "platform": "linux|macos|windows|office-365|gcp|azure-ad|aws|azure|saas",
    "tid": "T1110.001",
    "technique": "Password Guessing",
    "tactic": "credential-access",
    "datasources": "authentication-logs|office-365-account-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts.<br /><br />Guessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. (Citation: Cylance Cleaver)<br /><br />Typically, management services over commonly used ports are used when guessing passwords. Commonly targeted services include the following:<br /><br />* SSH (22/TCP)<br /><br />* Telnet (23/TCP)<br /><br />* FTP (21/TCP)<br /><br />* NetBIOS / SMB / Samba (139/TCP & 445/TCP)<br /><br />* LDAP (389/TCP)<br /><br />* Kerberos (88/TCP)<br /><br />* RDP / Terminal Services (3389/TCP)<br /><br />* HTTP/HTTP Management Services (80/TCP & 443/TCP)<br /><br />* MSSQL (1433/TCP)<br /><br />* Oracle (1521/TCP)<br /><br />* MySQL (3306/TCP)<br /><br />* VNC (5900/TCP)<br /><br />In addition to management services, adversaries may \"target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols,\" as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)<br /><br />In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows \"logon failure\" event ID 4625.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/49.html",
        "description": "none",
        "external_id": "CAPEC-49"
      },
      {
        "source_name": "Cylance Cleaver",
        "url": "https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf",
        "description": "Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "US-CERT TA18-068A 2018",
        "url": "https://www.us-cert.gov/ncas/alerts/TA18-086A",
        "description": "US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1d24cdee-9ea2-4189-b08e-af110bf2435d",
    "platform": "linux|macos|windows|office-365|azure-ad",
    "tid": "T1110.002",
    "technique": "Password Cracking",
    "tactic": "credential-access",
    "datasources": "authentication-logs|office-365-account-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) is used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) is not an option. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network.(Citation: Wikipedia Password cracking) The resulting plaintext password resulting from a successfully cracked hash may be used to log into systems, resources, and services in which the account has access.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/55.html",
        "description": "none",
        "external_id": "CAPEC-55"
      },
      {
        "source_name": "Wikipedia Password cracking",
        "url": "https://en.wikipedia.org/wiki/Password_cracking",
        "description": "Wikipedia. (n.d.). Password cracking. Retrieved December 23, 2015.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--692074ae-bb62-4a5e-a735-02cb6bde458c",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1110.003",
    "technique": "Password Spraying",
    "tactic": "credential-access",
    "datasources": "authentication-logs|office-365-account-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)<br /><br />Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:<br /><br />* SSH (22/TCP)<br /><br />* Telnet (23/TCP)<br /><br />* FTP (21/TCP)<br /><br />* NetBIOS / SMB / Samba (139/TCP & 445/TCP)<br /><br />* LDAP (389/TCP)<br /><br />* Kerberos (88/TCP)<br /><br />* RDP / Terminal Services (3389/TCP)<br /><br />* HTTP/HTTP Management Services (80/TCP & 443/TCP)<br /><br />* MSSQL (1433/TCP)<br /><br />* Oracle (1521/TCP)<br /><br />* MySQL (3306/TCP)<br /><br />* VNC (5900/TCP)<br /><br />In addition to management services, adversaries may \"target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols,\" as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)<br /><br />In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows \"logon failure\" event ID 4625.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/565.html",
        "description": "none",
        "external_id": "CAPEC-565"
      },
      {
        "source_name": "BlackHillsInfosec Password Spraying",
        "url": "http://www.blackhillsinfosec.com/?p=4645",
        "description": "Thyer, J. (2015, October 30). Password Spraying & Other Fun with RPCCLIENT. Retrieved April 25, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "US-CERT TA18-068A 2018",
        "url": "https://www.us-cert.gov/ncas/alerts/TA18-086A",
        "description": "US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Trimarc Detecting Password Spraying",
        "url": "https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing",
        "description": "Metcalf, S. (2018, May 6). Trimarc Research: Detecting Password Spraying with Security Event Auditing. Retrieved January 16, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b2d03cea-aec1-45ca-9744-9ee583c1e1cc",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1110.004",
    "technique": "Credential Stuffing",
    "tactic": "credential-access",
    "datasources": "authentication-logs|office-365-account-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed. The information may be useful to an adversary attempting to compromise accounts by taking advantage of the tendency for users to use the same passwords across personal and business accounts.<br /><br />Credential stuffing is a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies.<br /><br />Typically, management services over commonly used ports are used when stuffing credentials. Commonly targeted services include the following:<br /><br />* SSH (22/TCP)<br /><br />* Telnet (23/TCP)<br /><br />* FTP (21/TCP)<br /><br />* NetBIOS / SMB / Samba (139/TCP & 445/TCP)<br /><br />* LDAP (389/TCP)<br /><br />* Kerberos (88/TCP)<br /><br />* RDP / Terminal Services (3389/TCP)<br /><br />* HTTP/HTTP Management Services (80/TCP & 443/TCP)<br /><br />* MSSQL (1433/TCP)<br /><br />* Oracle (1521/TCP)<br /><br />* MySQL (3306/TCP)<br /><br />* VNC (5900/TCP)<br /><br />In addition to management services, adversaries may \"target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols,\" as well as externally facing email applications, such as Office 365.(Citation: US-CERT TA18-068A 2018)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/600.html",
        "description": "none",
        "external_id": "CAPEC-600"
      },
      {
        "source_name": "US-CERT TA18-068A 2018",
        "url": "https://www.us-cert.gov/ncas/alerts/TA18-086A",
        "description": "US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--837f9164-50af-4ac0-8219-379d8a74cefc",
    "platform": "linux|macos|windows|aws|gcp|azure",
    "tid": "T1552.001",
    "technique": "Credentials In Files",
    "tactic": "credential-access",
    "datasources": "file-monitoring|process-command-line-parameters",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.<br /><br />It is possible to extract passwords from backups or saved virtual machines through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). (Citation: CG 2014) Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller. (Citation: SRD GPP)<br /><br />In cloud environments, authenticated user credentials are often stored in local configuration and credential files. In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files. (Citation: Specter Ops - Cloud Credential Storage)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/639.html",
        "description": "none",
        "external_id": "CAPEC-639"
      },
      {
        "source_name": "CG 2014",
        "url": "http://carnal0wnage.attackresearch.com/2014/05/mimikatz-against-virtual-machine-memory.html",
        "description": "CG. (2014, May 20). Mimikatz Against Virtual Machine Memory Part 1. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "SRD GPP",
        "url": "http://blogs.technet.com/b/srd/archive/2014/05/13/ms14-025-an-update-for-group-policy-preferences.aspx",
        "description": "Security Research and Defense. (2014, May 13). MS14-025: An Update for Group Policy Preferences. Retrieved January 28, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "Specter Ops - Cloud Credential Storage",
        "url": "https://posts.specterops.io/head-in-the-clouds-bd038bb69e48",
        "description": "Maddalena, C.. (2018, September 12). Head in the Clouds. Retrieved October 4, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--341e222a-a6e3-4f6f-b69c-831d792b1580",
    "platform": "windows",
    "tid": "T1552.002",
    "technique": "Credentials in Registry",
    "tactic": "credential-access",
    "datasources": "process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons.<br /><br />Example commands to find Registry keys related to password information: (Citation: Pentestlab Stored Credentials)<br /><br />* Local Machine Hive: <code>reg query HKLM /f password /t REG_SZ /s</code><br /><br />* Current User Hive: <code>reg query HKCU /f password /t REG_SZ /s</code><br /><br />",
    "technique_references": [
      {
        "source_name": "Pentestlab Stored Credentials",
        "url": "https://pentestlab.blog/2017/04/19/stored-credentials/",
        "description": "netbiosX. (2017, April 19). Stored Credentials. Retrieved April 6, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--8187bd2a-866f-4457-9009-86b0ddedffa3",
    "platform": "linux|macos",
    "tid": "T1552.003",
    "technique": "Bash History",
    "tactic": "credential-access",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may search the bash command history on compromised systems for insecurely stored credentials. Bash keeps track of the commands users type on the command-line with the \"history\" utility. Once a user logs out, the history is flushed to the user’s <code>.bash_history</code> file. For each user, this file resides at the same location: <code>~/.bash_history</code>. Typically, this file keeps track of the user’s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Attackers can abuse this by looking through the file for potential credentials. (Citation: External to DA, the OS X Way)<br /><br />",
    "technique_references": [
      {
        "source_name": "External to DA, the OS X Way",
        "url": "http://www.slideshare.net/StephanBorosh/external-to-da-the-os-x-way",
        "description": "Alex Rymdeko-Harvey, Steve Borosh. (2016, May 14). External to DA, the OS X Way. Retrieved July 3, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--60b508a1-6a5e-46b1-821a-9f7b78752abf",
    "platform": "linux|macos|windows",
    "tid": "T1552.004",
    "technique": "Private Keys",
    "tactic": "credential-access",
    "datasources": "file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.(Citation: Wikipedia Public Key Crypto) Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc. <br /><br />Adversaries may also look in common key directories, such as <code>~/.ssh</code> for SSH keys on * nix-based systems or <code>C:&#92;Users&#92;(username)&#92;.ssh&#92;</code> on Windows. These private keys can be used to authenticate to [Remote Services](https://attack.mitre.org/techniques/T1021) like SSH or for use in decrypting other collected files such as email.<br /><br />Adversary tools have been discovered that search compromised systems for file extensions relating to cryptographic keys and certificates.(Citation: Kaspersky Careto)(Citation: Palo Alto Prince of Persia)<br /><br />Some private keys require a password or passphrase for operation, so an adversary may also use [Input Capture](https://attack.mitre.org/techniques/T1056) for keylogging or attempt to [Brute Force](https://attack.mitre.org/techniques/T1110) the passphrase off-line.<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia Public Key Crypto",
        "url": "https://en.wikipedia.org/wiki/Public-key_cryptography",
        "description": "Wikipedia. (2017, June 29). Public-key cryptography. Retrieved July 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Kaspersky Careto",
        "url": "https://kasperskycontenthub.com/wp-content/uploads/sites/43/vlpdfs/unveilingthemask_v1.0.pdf",
        "description": "Kaspersky Labs. (2014, February 11). Unveiling “Careto” - The Masked APT. Retrieved July 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Palo Alto Prince of Persia",
        "url": "https://researchcenter.paloaltonetworks.com/2016/06/unit42-prince-of-persia-game-over/",
        "description": "Bar, T., Conant, S., Efraim, L. (2016, June 28). Prince of Persia – Game Over. Retrieved July 5, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--19bf235b-8620-4997-b5b4-94e0659ed7c3",
    "platform": "aws|gcp|azure",
    "tid": "T1552.005",
    "technique": "Cloud Instance Metadata API",
    "tactic": "credential-access",
    "datasources": "authentication-logs|aws-cloudtrail-logs|azure-activity-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.<br /><br />Most cloud service providers support a Cloud Instance Metadata API which is a service provided to running virtual instances that allows applications to access information about the running virtual instance. Available information generally includes name, security group, and additional metadata including sensitive data such as credentials and UserData scripts that may contain additional secrets. The Instance Metadata API is provided as a convenience to assist in managing applications and is accessible by anyone who can access the instance.(Citation: AWS Instance Metadata API) A cloud metadata API has been used in at least one high profile compromise.(Citation: Krebs Capital One August 2019)<br /><br />If adversaries have a presence on the running virtual instance, they may query the Instance Metadata API directly to identify credentials that grant access to additional resources. Additionally, attackers may exploit a Server-Side Request Forgery (SSRF) vulnerability in a public facing web proxy that allows the attacker to gain access to the sensitive information via a request to the Instance Metadata API.(Citation: RedLock Instance Metadata API 2018)<br /><br />The de facto standard across cloud service providers is to host the Instance Metadata API at <code>http[:]//169.254.169.254</code>.<br /><br />",
    "technique_references": [
      {
        "source_name": "AWS Instance Metadata API",
        "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html",
        "description": "AWS. (n.d.). Instance Metadata and User Data. Retrieved July 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Krebs Capital One August 2019",
        "url": "https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/",
        "description": "Krebs, B.. (2019, August 19). What We Can Learn from the Capital One Hack. Retrieved March 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "RedLock Instance Metadata API 2018",
        "url": "https://redlock.io/blog/instance-metadata-api-a-modern-day-trojan-horse",
        "description": "Higashi, Michael. (2018, May 15). Instance Metadata API: A Modern Day Trojan Horse. Retrieved July 16, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--8d7bd4f5-3a89-4453-9c82-2c8894d5655e",
    "platform": "windows",
    "tid": "T1552.006",
    "technique": "Group Policy Preferences",
    "tactic": "credential-access",
    "datasources": "process-command-line-parameters|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts.(Citation: Microsoft GPP 2016)<br /><br />These group policies are stored in SYSVOL on a domain controller. This means that any domain user can view the SYSVOL share and decrypt the password (using the AES key that has been made public).(Citation: Microsoft GPP Key)<br /><br />The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:<br /><br />* Metasploit’s post exploitation module: <code>post/windows/gather/credentials/gpp</code><br /><br />* Get-GPPPassword(Citation: Obscuresecurity Get-GPPPassword)<br /><br />* gpprefdecrypt.py<br /><br />On the SYSVOL share, adversaries may use the following command to enumerate potential GPP XML files: <code>dir /s * .xml</code><br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft GPP 2016",
        "url": "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v%3Dws.11)",
        "description": "Microsoft. (2016, August 31). Group Policy Preferences. Retrieved March 9, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft GPP Key",
        "url": "https://msdn.microsoft.com/library/cc422924.aspx",
        "description": "Microsoft. (n.d.). 2.2.1.1.4 Password Encryption. Retrieved April 11, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Obscuresecurity Get-GPPPassword",
        "url": "https://obscuresecurity.blogspot.co.uk/2012/05/gpp-password-retrieval-with-powershell.html",
        "description": "Campbell, C. (2012, May 24). GPP Password Retrieval with PowerShell. Retrieved April 11, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "ADSecurity Finding Passwords in SYSVOL",
        "url": "https://adsecurity.org/?p=2288",
        "description": "Sean Metcalf. (2015, December 28). Finding Passwords in SYSVOL & Exploiting Group Policy Preferences. Retrieved February 17, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1eaebf46-e361-4437-bc23-d5d65a3b92e3",
    "platform": "macos",
    "tid": "T1555.001",
    "technique": "Keychain",
    "tactic": "credential-access",
    "datasources": "api-monitoring|file-monitoring|powershell-logs|process-monitoring|system-calls",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may collect the keychain storage data from a system to acquire credentials. Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features such as WiFi passwords, websites, secure notes, certificates, and Kerberos. Keychain files are located in <code>~/Library/Keychains/</code>,<code>/Library/Keychains/</code>, and <code>/Network/Library/Keychains/</code>. (Citation: Wikipedia keychain) The <code>security</code> command-line utility, which is built into macOS by default, provides a useful way to manage these credentials.<br /><br />To manage their credentials, users have to use additional credentials to access their keychain. If an adversary knows the credentials for the login keychain, then they can get access to all the other credentials stored in this vault. (Citation: External to DA, the OS X Way) By default, the passphrase for the keychain is the user’s logon credentials.<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia keychain",
        "url": "https://en.wikipedia.org/wiki/Keychain_(software)",
        "description": "Wikipedia. (n.d.). Keychain (software). Retrieved July 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "External to DA, the OS X Way",
        "url": "http://www.slideshare.net/StephanBorosh/external-to-da-the-os-x-way",
        "description": "Alex Rymdeko-Harvey, Steve Borosh. (2016, May 14). External to DA, the OS X Way. Retrieved July 3, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1a80d097-54df-41d8-9d33-34e755ec5e72",
    "platform": "linux|macos",
    "tid": "T1555.002",
    "technique": "Securityd Memory",
    "tactic": "credential-access",
    "datasources": "process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may obtain root access (allowing them to read securityd’s memory), then they can scan through memory to find the correct sequence of keys in relatively few tries to decrypt the user’s logon keychain. This provides the adversary with all the plaintext passwords for users, WiFi, mail, browsers, certificates, secure notes, etc.(Citation: OS X Keychain) (Citation: OSX Keydnap malware)<br /><br />In OS X prior to El Capitan, users with root access can read plaintext keychain passwords of logged-in users because Apple’s keychain implementation allows these credentials to be cached so that users are not repeatedly prompted for passwords. (Citation: OS X Keychain) (Citation: External to DA, the OS X Way) Apple’s securityd utility takes the user’s logon password, encrypts it with PBKDF2, and stores this master key in memory. Apple also uses a set of keys and algorithms to encrypt the user’s password, but once the master key is found, an attacker need only iterate over the other values to unlock the final password.(Citation: OS X Keychain)<br /><br />",
    "technique_references": [
      {
        "source_name": "OS X Keychain",
        "url": "http://juusosalonen.com/post/30923743427/breaking-into-the-os-x-keychain",
        "description": "Juuso Salonen. (2012, September 5). Breaking into the OS X keychain. Retrieved July 15, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "OSX Keydnap malware",
        "url": "https://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-hungry-credentials/",
        "description": "Marc-Etienne M.Leveille. (2016, July 6). New OSX/Keydnap malware is hungry for credentials. Retrieved July 3, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "External to DA, the OS X Way",
        "url": "http://www.slideshare.net/StephanBorosh/external-to-da-the-os-x-way",
        "description": "Alex Rymdeko-Harvey, Steve Borosh. (2016, May 14). External to DA, the OS X Way. Retrieved July 3, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--58a3e6aa-4453-4cc8-a51f-4befe80b31a8",
    "platform": "linux|macos|windows",
    "tid": "T1555.003",
    "technique": "Credentials from Web Browsers",
    "tactic": "credential-access",
    "datasources": "api-monitoring|file-monitoring|powershell-logs|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may acquire credentials from web browsers by reading files specific to the target browser.(Citation: Talos Olympic Destroyer 2018) Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.<br /><br />For example, on Windows systems, encrypted credentials may be obtained from Google Chrome by reading a database file, <code>AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data</code> and executing a SQL query: <code>SELECT action_url, username_value, password_value FROM logins;</code>. The plaintext password can then be obtained by passing the encrypted credentials to the Windows API function <code>CryptUnprotectData</code>, which uses the victim’s cached logon credentials as the decryption key. (Citation: Microsoft CryptUnprotectData ‎April 2018)<br /><br /> <br /><br />Adversaries have executed similar procedures for common web browsers such as FireFox, Safari, Edge, etc. (Citation: Proofpoint Vega Credential Stealer May 2018)(Citation: FireEye HawkEye Malware July 2017)<br /><br />Adversaries may also acquire credentials by searching web browser process memory for patterns that commonly match credentials.(Citation: GitHub Mimikittenz July 2016)<br /><br />After acquiring credentials from web browsers, adversaries may attempt to recycle the credentials across different systems and/or accounts in order to expand access. This can result in significantly furthering an adversary's objective in cases where credentials gained from web browsers overlap with privileged accounts (e.g. domain administrator).<br /><br />",
    "technique_references": [
      {
        "source_name": "Talos Olympic Destroyer 2018",
        "url": "https://blog.talosintelligence.com/2018/02/olympic-destroyer.html",
        "description": "Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft CryptUnprotectData ‎April 2018",
        "url": "https://docs.microsoft.com/en-us/windows/desktop/api/dpapi/nf-dpapi-cryptunprotectdata",
        "description": "Microsoft. (2018, April 12). CryptUnprotectData function. Retrieved June 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Proofpoint Vega Credential Stealer May 2018",
        "url": "https://www.proofpoint.com/us/threat-insight/post/new-vega-stealer-shines-brightly-targeted-campaign",
        "description": "Proofpoint. (2018, May 10). New Vega Stealer shines brightly in targeted campaign . Retrieved June 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye HawkEye Malware July 2017",
        "url": "https://www.fireeye.com/blog/threat-research/2017/07/hawkeye-malware-distributed-in-phishing-campaign.html",
        "description": "Swapnil Patil, Yogesh Londhe. (2017, July 25). HawkEye Credential Theft Malware Distributed in Recent Phishing Campaign. Retrieved June 18, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Mimikittenz July 2016",
        "url": "https://github.com/putterpanda/mimikittenz",
        "description": "Jamieson O'Reilly (putterpanda). (2016, July 4). mimikittenz. Retrieved June 20, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d4b96d2c-1032-4b22-9235-2b5b649d0605",
    "platform": "windows",
    "tid": "T1556.001",
    "technique": "Domain Controller Authentication",
    "tactic": "credential-access",
    "datasources": "api-monitoring|authentication-logs|dll-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts. <br /><br />Malware may be used to inject false credentials into the authentication process on a domain controller with the intent of creating a backdoor used to access any user’s account and/or credentials (ex: [Skeleton Key](https://attack.mitre.org/software/S0007)). Skeleton key works through a patch on an enterprise domain controller authentication process (LSASS) with credentials that adversaries may use to bypass the standard authentication system. Once patched, an adversary can use the injected password to successfully authenticate as any domain user account (until the the skeleton key is erased from memory by a reboot of the domain controller). Authenticated access may enable unfettered access to hosts and/or resources within single-factor authentication environments.(Citation: Dell Skeleton)<br /><br />",
    "technique_references": [
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
    "id": "attack-pattern--3731fbcd-0e43-47ae-ae6c-d15e510f0d42",
    "platform": "windows",
    "tid": "T1556.002",
    "technique": "Password Filter DLL",
    "tactic": "credential-access",
    "datasources": "dll-monitoring|file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated. <br /><br />Windows password filters are password policy enforcement mechanisms for both domain and local accounts. Filters are implemented as DLLs containing a method to validate potential passwords against password policies. Filter DLLs can be positioned on local computers for local accounts and/or domain controllers for domain accounts. Before registering new passwords in the Security Accounts Manager (SAM), the Local Security Authority (LSA) requests validation from each registered filter. Any potential changes cannot take effect until every registered filter acknowledges validation. <br /><br />Adversaries can register malicious password filters to harvest credentials from local computers and/or entire domains. To perform proper validation, filters must receive plain-text credentials from the LSA. A malicious password filter would receive these plain-text credentials every time a password request is made.(Citation: Carnal Ownage Password Filters Sept 2013)<br /><br />",
    "technique_references": [
      {
        "source_name": "Carnal Ownage Password Filters Sept 2013",
        "url": "http://carnal0wnage.attackresearch.com/2013/09/stealing-passwords-every-time-they.html",
        "description": "Fuller, R. (2013, September 11). Stealing passwords every time they change. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Clymb3r Function Hook Passwords Sept 2013",
        "url": "https://clymb3r.wordpress.com/2013/09/15/intercepting-password-changes-with-function-hooking/",
        "description": "Bialek, J. (2013, September 15). Intercepting Password Changes With Function Hooking. Retrieved November 21, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--06c00069-771a-4d57-8ef5-d3718c1a8771",
    "platform": "linux|macos",
    "tid": "T1556.003",
    "technique": "Pluggable Authentication Modules",
    "tactic": "credential-access",
    "datasources": "authentication-logs|file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is <code>pam_unix.so</code>, which retrieves, sets, and verifies account authentication information in <code>/etc/passwd</code> and <code>/etc/shadow</code>.(Citation: Apple PAM)(Citation: Man Pam_Unix)(Citation: Red Hat PAM)<br /><br />Adversaries may modify components of the PAM system to create backdoors. PAM components, such as <code>pam_unix.so</code>, can be patched to accept arbitrary adversary supplied values as legitimate credentials.(Citation: PAM Backdoor)<br /><br />Malicious modifications to the PAM system may also be abused to steal credentials. Adversaries may infect PAM resources with code to harvest user credentials, since the values exchanged with PAM components may be plain-text since PAM does not store passwords.(Citation: PAM Creds)(Citation: Apple PAM)<br /><br />",
    "technique_references": [
      {
        "source_name": "Apple PAM",
        "url": "https://opensource.apple.com/source/dovecot/dovecot-239/dovecot/doc/wiki/PasswordDatabase.PAM.txt",
        "description": "Apple. (2011, May 11). PAM - Pluggable Authentication Modules. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Man Pam_Unix",
        "url": "https://linux.die.net/man/8/pam_unix",
        "description": "die.net. (n.d.). pam_unix(8) - Linux man page. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Red Hat PAM",
        "url": "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/managing_smart_cards/pluggable_authentication_modules",
        "description": "Red Hat. (n.d.). CHAPTER 2. USING PLUGGABLE AUTHENTICATION MODULES (PAM). Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "PAM Backdoor",
        "url": "https://github.com/zephrax/linux-pam-backdoor",
        "description": "zephrax. (2018, August 3). linux-pam-backdoor. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "PAM Creds",
        "url": "https://x-c3ll.github.io/posts/PAM-backdoor-DNS/",
        "description": "Fernández, J. M. (2018, June 27). Exfiltrating credentials via PAM backdoors & DNS requests. Retrieved June 26, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--fa44a152-ac48-441e-a524-dd7b04b8adcd",
    "platform": "network",
    "tid": "T1556.004",
    "technique": "Network Device Authentication",
    "tactic": "credential-access",
    "datasources": "file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use [Patch System Image](https://attack.mitre.org/techniques/T1601/001) to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices.<br /><br />[Modify System Image](https://attack.mitre.org/techniques/T1601) may include implanted code to the operating system for network devices to provide access for adversaries using a specific password.  The modification includes a specific password which is implanted in the operating system image via the patch.  Upon authentication attempts, the inserted code will first check to see if the user input is the password. If so, access is granted. Otherwise, the implanted code will pass the credentials on for verification of potentially valid credentials.(Citation: FireEye - Synful Knock)<br /><br />",
    "technique_references": [
      {
        "source_name": "FireEye - Synful Knock",
        "url": "https://www.fireeye.com/blog/threat-research/2015/09/synful_knock_-_acis.html",
        "description": "Bill Hau, Tony Lee, Josh Homan. (2015, September 15). SYNful Knock - A Cisco router implant - Part I. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco IOS Software Integrity Assurance - Image File Verification",
        "url": "https://tools.cisco.com/security/center/resources/integrity_assurance.html#7",
        "description": "Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Cisco IOS Image File Verification. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco IOS Software Integrity Assurance - Run-Time Memory Verification",
        "url": "https://tools.cisco.com/security/center/resources/integrity_assurance.html#13",
        "description": "Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Cisco IOS Run-Time Memory Integrity Verification. Retrieved October 19, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--650c784b-7504-4df7-ab2c-4ea882384d1e",
    "platform": "windows",
    "tid": "T1557.001",
    "technique": "LLMNR/NBT-NS Poisoning and SMB Relay",
    "tactic": "credential-access",
    "datasources": "netflow-enclave-netflow|packet-capture|windows-event-logs|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials. <br /><br />Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. NBT-NS identifies systems on a local network by their NetBIOS name. (Citation: Wikipedia LLMNR) (Citation: TechNet NetBIOS)<br /><br />Adversaries can spoof an authoritative source for name resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they know the identity of the requested host, effectively poisoning the service so that the victims will communicate with the adversary controlled system. If the requested host belongs to a resource that requires identification/authentication, the username and NTLMv2 hash will then be sent to the adversary controlled system. The adversary can then collect the hash information sent over the wire through tools that monitor the ports for traffic or through [Network Sniffing](https://attack.mitre.org/techniques/T1040) and crack the hashes offline through [Brute Force](https://attack.mitre.org/techniques/T1110) to obtain the plaintext passwords. In some cases where an adversary has access to a system that is in the authentication path between systems or when automated scans that use credentials attempt to authenticate to an adversary controlled system, the NTLMv2 hashes can be intercepted and relayed to access and execute code against a target system. The relay step can happen in conjunction with poisoning but may also be independent of it. (Citation: byt3bl33d3r NTLM Relaying)(Citation: Secure Ideas SMB Relay)<br /><br />Several tools exist that can be used to poison name services within local networks such as NBNSpoof, Metasploit, and [Responder](https://attack.mitre.org/software/S0174). (Citation: GitHub NBNSpoof) (Citation: Rapid7 LLMNR Spoofer) (Citation: GitHub Responder)<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia LLMNR",
        "url": "https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution",
        "description": "Wikipedia. (2016, July 7). Link-Local Multicast Name Resolution. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet NetBIOS",
        "url": "https://technet.microsoft.com/library/cc958811.aspx",
        "description": "Microsoft. (n.d.). NetBIOS Name Resolution. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "byt3bl33d3r NTLM Relaying",
        "url": "https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html",
        "description": "Salvati, M. (2017, June 2). Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes). Retrieved February 7, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Secure Ideas SMB Relay",
        "url": "https://blog.secureideas.com/2018/04/ever-run-a-relay-why-smb-relays-should-be-on-your-mind.html",
        "description": "Kuehn, E. (2018, April 11). Ever Run a Relay? Why SMB Relays Should Be On Your Mind. Retrieved February 7, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub NBNSpoof",
        "url": "https://github.com/nomex/nbnspoof",
        "description": "Nomex. (2014, February 7). NBNSpoof. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Rapid7 LLMNR Spoofer",
        "url": "https://www.rapid7.com/db/modules/auxiliary/spoof/llmnr/llmnr_response",
        "description": "Francois, R. (n.d.). LLMNR Spoofer. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Responder",
        "url": "https://github.com/SpiderLabs/Responder",
        "description": "Gaffie, L. (2016, August 25). Responder. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Sternsecurity LLMNR-NBTNS",
        "url": "https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning",
        "description": "Sternstein, J. (2013, November). Local Network Attacks: LLMNR and NBT-NS Poisoning. Retrieved November 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Conveigh",
        "url": "https://github.com/Kevin-Robertson/Conveigh",
        "description": "Robertson, K. (2016, August 28). Conveigh. Retrieved November 17, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cabe189c-a0e3-4965-a473-dcff00f17213",
    "platform": "linux|windows|macos",
    "tid": "T1557.002",
    "technique": "ARP Cache Poisoning",
    "tactic": "credential-access",
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
    "technique_description": "Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002).<br /><br />The ARP protocol is used to resolve IPv4 addresses to link layer addresses, such as a media access control (MAC) address.(Citation: RFC826 ARP) Devices in a local network segment communicate with each other by using link layer addresses. If a networked device does not have the link layer address of a particular networked device, it may send out a broadcast ARP request to the local network to translate the IP address to a MAC address. The device with the associated IP address directly replies with its MAC address. The networked device that made the ARP request will then use as well as store that information in its ARP cache.<br /><br />An adversary may passively wait for an ARP request to poison the ARP cache of the requesting device. The adversary may reply with their MAC address, thus deceiving the victim by making them believe that they are communicating with the intended networked device. For the adversary to poison the ARP cache, their reply must be faster than the one made by the legitimate IP address owner. Adversaries may also send a gratuitous ARP reply that maliciously announces the ownership of a particular IP address to all the devices in the local network segment.<br /><br />The ARP protocol is stateless and does not require authentication. Therefore, devices may wrongly add or update the MAC address of the IP address in their ARP cache.(Citation: Sans ARP Spoofing Aug 2003)(Citation: Cylance Cleaver)<br /><br />Adversaries may use ARP cache poisoning as a means to man-in-the-middle (MiTM) network traffic. This activity may be used to collect and/or relay data such as credentials, especially those sent over an insecure, unencrypted protocol.(Citation: Sans ARP Spoofing Aug 2003)<br /><br />",
    "technique_references": [
      {
        "source_name": "RFC826 ARP",
        "url": "https://tools.ietf.org/html/rfc826",
        "description": "Plummer, D. (1982, November). An Ethernet Address Resolution Protocol. Retrieved October 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Sans ARP Spoofing Aug 2003",
        "url": "https://pen-testing.sans.org/resources/papers/gcih/real-world-arp-spoofing-105411",
        "description": "Siles, R. (2003, August). Real World ARP Spoofing. Retrieved October 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cylance Cleaver",
        "url": "https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf",
        "description": "Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--768dce68-8d0d-477a-b01d-0eea98b963a1",
    "platform": "windows",
    "tid": "T1558.001",
    "technique": "Golden Ticket",
    "tactic": "credential-access",
    "datasources": "authentication-logs|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.(Citation: AdSecurity Kerberos GT Aug 2015) Golden tickets enable adversaries to generate authentication material for any account in Active Directory.(Citation: CERT-EU Golden Ticket Protection) <br /><br />Using a golden ticket, adversaries are then able to request ticket granting service (TGS) tickets, which enable access to specific resources. Golden tickets require adversaries to interact with the Key Distribution Center (KDC) in order to obtain TGS.(Citation: ADSecurity Detecting Forged Tickets)<br /><br />The KDC service runs all on domain controllers that are part of an Active Directory domain. KRBTGT is the Kerberos Key Distribution Center (KDC) service account and is responsible for encrypting and signing all Kerberos tickets.(Citation: ADSecurity Kerberos and KRBTGT) The KRBTGT password hash may be obtained using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) and privileged access to a domain controller.<br /><br />",
    "technique_references": [
      {
        "source_name": "AdSecurity Kerberos GT Aug 2015",
        "url": "https://adsecurity.org/?p=1640",
        "description": "Metcalf, S. (2015, August 7). Kerberos Golden Tickets are Now More Golden. Retrieved December 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "CERT-EU Golden Ticket Protection",
        "url": "https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf",
        "description": "Abolins, D., Boldea, C., Socha, K., Soria-Machado, M. (2016, April 26). Kerberos Golden Ticket Protection. Retrieved July 13, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "ADSecurity Detecting Forged Tickets",
        "url": "https://adsecurity.org/?p=1515",
        "description": "Metcalf, S. (2015, May 03). Detecting Forged Kerberos Ticket (Golden Ticket & Silver Ticket) Use in Active Directory. Retrieved December 23, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "ADSecurity Kerberos and KRBTGT",
        "url": "https://adsecurity.org/?p=483",
        "description": "Sean Metcalf. (2014, November 10). Kerberos & KRBTGT: Active Directory’s Domain Kerberos Service Account. Retrieved January 30, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Stealthbits Detect PtT 2019",
        "url": "https://blog.stealthbits.com/detect-pass-the-ticket-attacks",
        "description": "Jeff Warren. (2019, February 19). How to Detect Pass-the-Ticket Attacks. Retrieved February 27, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Kerberos Golden Ticket",
        "url": "https://gallery.technet.microsoft.com/scriptcenter/Kerberos-Golden-Ticket-b4814285",
        "description": "Microsoft. (2015, March 24). Kerberos Golden Ticket Check (Updated). Retrieved February 27, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d273434a-448e-4598-8e14-607f4a0d5e27",
    "platform": "windows",
    "tid": "T1558.002",
    "technique": "Silver Ticket",
    "tactic": "credential-access",
    "datasources": "authentication-logs|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Kerberos TGS tickets are also known as service tickets.(Citation: ADSecurity Silver Tickets)<br /><br />Silver tickets are more limited in scope in than golden tickets in that they only enable adversaries to access a particular resource (e.g. MSSQL) and the system that hosts the resource; however, unlike golden tickets, adversaries with the ability to forge silver tickets are able to create TGS tickets without interacting with the Key Distribution Center (KDC), potentially making detection more difficult.(Citation: ADSecurity Detecting Forged Tickets)<br /><br />Password hashes for target services may be obtained using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) or [Kerberoasting](https://attack.mitre.org/techniques/T1558/003).<br /><br />",
    "technique_references": [
      {
        "source_name": "ADSecurity Silver Tickets",
        "url": "https://adsecurity.org/?p=2011",
        "description": "Sean Metcalf. (2015, November 17). How Attackers Use Kerberos Silver Tickets to Exploit Systems. Retrieved February 27, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ADSecurity Detecting Forged Tickets",
        "url": "https://adsecurity.org/?p=1515",
        "description": "Metcalf, S. (2015, May 03). Detecting Forged Kerberos Ticket (Golden Ticket & Silver Ticket) Use in Active Directory. Retrieved December 23, 2015.",
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
    "id": "attack-pattern--f2877f7f-9a4c-4251-879f-1224e3006bee",
    "platform": "windows",
    "tid": "T1558.003",
    "technique": "Kerberoasting",
    "tactic": "credential-access",
    "datasources": "authentication-logs|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to [Brute Force](https://attack.mitre.org/techniques/T1110).(Citation: Empire InvokeKerberoast Oct 2016)(Citation: AdSecurity Cracking Kerberos Dec 2015) <br /><br />Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service(Citation: Microsoft Detecting Kerberoasting Feb 2018)).(Citation: Microsoft SPN)(Citation: Microsoft SetSPN)(Citation: SANS Attacking Kerberos Nov 2014)(Citation: Harmj0y Kerberoast Nov 2016)<br /><br />Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC).(Citation: Empire InvokeKerberoast Oct 2016)(Citation: AdSecurity Cracking Kerberos Dec 2015) Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline [Brute Force](https://attack.mitre.org/techniques/T1110) attacks that may expose plaintext credentials.(Citation: AdSecurity Cracking Kerberos Dec 2015)(Citation: Empire InvokeKerberoast Oct 2016) (Citation: Harmj0y Kerberoast Nov 2016)<br /><br />This same attack could be executed using service tickets captured from network traffic.(Citation: AdSecurity Cracking Kerberos Dec 2015)<br /><br />Cracked hashes may enable [Persistence](https://attack.mitre.org/tactics/TA0003), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004), and [Lateral Movement](https://attack.mitre.org/tactics/TA0008) via access to [Valid Accounts](https://attack.mitre.org/techniques/T1078).(Citation: SANS Attacking Kerberos Nov 2014)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/509.html",
        "description": "none",
        "external_id": "CAPEC-509"
      },
      {
        "source_name": "Empire InvokeKerberoast Oct 2016",
        "url": "https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1",
        "description": "EmpireProject. (2016, October 31). Invoke-Kerberoast.ps1. Retrieved March 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "AdSecurity Cracking Kerberos Dec 2015",
        "url": "https://adsecurity.org/?p=2293",
        "description": "Metcalf, S. (2015, December 31). Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain. Retrieved March 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Detecting Kerberoasting Feb 2018",
        "url": "https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/",
        "description": "Bani, M. (2018, February 23). Detecting Kerberoasting activity using Azure Security Center. Retrieved March 23, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SPN",
        "url": "https://msdn.microsoft.com/library/ms677949.aspx",
        "description": "Microsoft. (n.d.). Service Principal Names. Retrieved March 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SetSPN",
        "url": "https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx",
        "description": "Microsoft. (2010, April 13). Service Principal Names (SPNs) SetSPN Syntax (Setspn.exe). Retrieved March 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "SANS Attacking Kerberos Nov 2014",
        "url": "https://redsiege.com/kerberoast-slides",
        "description": "Medin, T. (2014, November). Attacking Kerberos - Kicking the Guard Dog of Hades. Retrieved March 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Harmj0y Kerberoast Nov 2016",
        "url": "https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/",
        "description": "Schroeder, W. (2016, November 1). Kerberoasting Without Mimikatz. Retrieved March 23, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3986e7fd-a8e9-4ecb-bfc6-55920855912b",
    "platform": "windows",
    "tid": "T1558.004",
    "technique": "AS-REP Roasting",
    "tactic": "credential-access",
    "datasources": "authentication-logs|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by [Password Cracking](https://attack.mitre.org/techniques/T1110/002) Kerberos messages.(Citation: Harmj0y Roasting AS-REPs Jan 2017) <br /><br />Preauthentication offers protection against offline [Password Cracking](https://attack.mitre.org/techniques/T1110/002). When enabled, a user requesting access to a resource initiates communication with the Domain Controller (DC) by sending an Authentication Server Request (AS-REQ) message with a timestamp that is encrypted with the hash of their password. If and only if the DC is able to successfully decrypt the timestamp with the hash of the user’s password, it will then send an Authentication Server Response (AS-REP) message that contains the Ticket Granting Ticket (TGT) to the user. Part of the AS-REP message is signed with the user’s password.(Citation: Microsoft Kerberos Preauth 2014)<br /><br />For each account found without preauthentication, an adversary may send an AS-REQ message without the encrypted timestamp and receive an AS-REP message with TGT data which may be encrypted with an insecure algorithm such as RC4. The recovered encrypted data may be vulnerable to offline [Password Cracking](https://attack.mitre.org/techniques/T1110/002) attacks similarly to [Kerberoasting](https://attack.mitre.org/techniques/T1558/003) and expose plaintext credentials. (Citation: Harmj0y Roasting AS-REPs Jan 2017)(Citation: Stealthbits Cracking AS-REP Roasting Jun 2019) <br /><br />An account registered to a domain, with or without special privileges, can be abused to list all domain accounts that have preauthentication disabled by utilizing Windows tools like [PowerShell](https://attack.mitre.org/techniques/T1059/001) with an LDAP filter. Alternatively, the adversary may send an AS-REQ message for each user. If the DC responds without errors, the account does not require preauthentication and the AS-REP message will already contain the encrypted data. (Citation: Harmj0y Roasting AS-REPs Jan 2017)(Citation: Stealthbits Cracking AS-REP Roasting Jun 2019)<br /><br />Cracked hashes may enable [Persistence](https://attack.mitre.org/tactics/TA0003), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004), and [Lateral Movement](https://attack.mitre.org/tactics/TA0008) via access to [Valid Accounts](https://attack.mitre.org/techniques/T1078).(Citation: SANS Attacking Kerberos Nov 2014)<br /><br />",
    "technique_references": [
      {
        "source_name": "Harmj0y Roasting AS-REPs Jan 2017",
        "url": "http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/",
        "description": "HarmJ0y. (2017, January 17). Roasting AS-REPs. Retrieved August 24, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Kerberos Preauth 2014",
        "url": "https://social.technet.microsoft.com/wiki/contents/articles/23559.kerberos-pre-authentication-why-it-should-not-be-disabled.aspx",
        "description": "Sanyal, M.. (2014, March 18). Kerberos Pre-Authentication: Why It Should Not Be Disabled. Retrieved August 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Stealthbits Cracking AS-REP Roasting Jun 2019",
        "url": "https://blog.stealthbits.com/cracking-active-directory-passwords-with-as-rep-roasting/",
        "description": "Jeff Warren. (2019, June 27). Cracking Active Directory Passwords with AS-REP Roasting. Retrieved August 24, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "SANS Attacking Kerberos Nov 2014",
        "url": "https://redsiege.com/kerberoast-slides",
        "description": "Medin, T. (2014, November). Attacking Kerberos - Kicking the Guard Dog of Hades. Retrieved March 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "AdSecurity Cracking Kerberos Dec 2015",
        "url": "https://adsecurity.org/?p=2293",
        "description": "Metcalf, S. (2015, December 31). Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain. Retrieved March 22, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Detecting Kerberoasting Feb 2018",
        "url": "https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/",
        "description": "Bani, M. (2018, February 23). Detecting Kerberoasting activity using Azure Security Center. Retrieved March 23, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft 4768 TGT 2017",
        "url": "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768",
        "description": "Microsoft. (2017, April 19). 4768(S, F): A Kerberos authentication ticket (TGT) was requested. Retrieved August 24, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--861b8fd2-57f3-4ee1-ab5d-c19c3b8c7a4a",
    "platform": "linux|macos|windows|saas",
    "tid": "T1606.001",
    "technique": "Web Cookies",
    "tactic": "credential-access",
    "datasources": "authentication-logs|web-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may forge web cookies that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies to authenticate and authorize user access.<br /><br />Adversaries may generate these cookies in order to gain access to web resources. This differs from [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539) and other similar behaviors in that the cookies are new and forged by the adversary, rather than stolen or intercepted from legitimate users. Most common web applications have standardized and documented cookie values that can be generated using provided tools or interfaces.(Citation: Pass The Cookie) The generation of web cookies often requires secret values, such as passwords, [Private Keys](https://attack.mitre.org/techniques/T1552/004), or other cryptographic seed values.<br /><br />Once forged, adversaries may use these web cookies to access resources ([Web Session Cookie](https://attack.mitre.org/techniques/T1550/004)), which may bypass multi-factor and other authentication protection mechanisms.(Citation: Volexity SolarWinds)(Citation: Pass The Cookie)(Citation: Unit 42 Mac Crypto Cookies January 2019)<br /><br />",
    "technique_references": [
      {
        "source_name": "Pass The Cookie",
        "url": "https://wunderwuzzi23.github.io/blog/passthecookie.html",
        "description": "Rehberger, J. (2018, December). Pivot to the Cloud using Pass the Cookie. Retrieved April 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Volexity SolarWinds",
        "url": "https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/",
        "description": "Cash, D. et al. (2020, December 14). Dark Halo Leverages SolarWinds Compromise to Breach Organizations. Retrieved December 29, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Unit 42 Mac Crypto Cookies January 2019",
        "url": "https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/",
        "description": "Chen, Y., Hu, W., Xu, Z., et. al. (2019, January 31). Mac Malware Steals Cryptocurrency Exchanges’ Cookies. Retrieved October 14, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1f9c2bae-b441-4f66-a8af-b65946ee72f2",
    "platform": "azure-ad|saas|windows|office-365",
    "tid": "T1606.002",
    "technique": "SAML Tokens",
    "tactic": "credential-access",
    "datasources": "authentication-logs|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate.(Citation: Microsoft SolarWinds Steps) The default lifetime of a SAML token is one hour, but the validity period can be specified in the <code>NotOnOrAfter</code> value of the <code>conditions ...</code> element in a token. This value can be changed using the <code>AccessTokenLifetime</code> in a <code>LifetimeTokenPolicy</code>.(Citation: Microsoft SAML Token Lifetimes) Forged SAML tokens enable adversaries to authenticate across services that use SAML 2.0 as an SSO (single sign-on) mechanism.(Citation: Cyberark Golden SAML)<br /><br />An adversary may utilize [Private Keys](https://attack.mitre.org/techniques/T1552/004) to compromise an organization's token-signing certificate to create forged SAML tokens. If the adversary has sufficient permissions to establish a new federation trust with their own Active Directory Federation Services (AD FS) server, they may instead generate their own trusted token-signing certificate.(Citation: Microsoft SolarWinds Customer Guidance) This differs from [Steal Application Access Token](https://attack.mitre.org/techniques/T1528) and other similar behaviors in that the tokens are new and forged by the adversary, rather than stolen or intercepted from legitimate users.<br /><br />An adversary may gain administrative Azure AD privileges if a SAML token is forged which claims to represent a highly privileged account. This may lead to [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550), which may bypass multi-factor and other authentication protection mechanisms.(Citation: Microsoft SolarWinds Customer Guidance)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft SolarWinds Steps",
        "url": "https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/",
        "description": "Lambert, J. (2020, December 13). Important steps for customers to protect themselves from recent nation-state cyberattacks. Retrieved December 17, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SAML Token Lifetimes",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes",
        "description": "Microsoft. (2020, December 14). Configurable token lifetimes in Microsoft Identity Platform. Retrieved December 22, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cyberark Golden SAML",
        "url": "https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps",
        "description": "Reiner, S. (2017, November 21). Golden SAML: Newly Discovered Attack Technique Forges Authentication to Cloud Apps. Retrieved December 17, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SolarWinds Customer Guidance",
        "url": "https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/",
        "description": "MSRC. (2020, December 13). Customer Guidance on Recent Nation-State Cyber Attacks. Retrieved December 17, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Sygnia Golden SAML",
        "url": "https://www.sygnia.co/golden-saml-advisory",
        "description": "Sygnia. (2020, December). Detection and Hunting of Golden SAML Attack. Retrieved January 6, 2021.",
        "external_id": "none"
      }
    ]
  }
]
