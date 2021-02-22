export const LATERAL_MOVEMENT_SUBTECHNIQUE_DETAILS = [
  {
    "id": "attack-pattern--eb062747-2193-45de-8fa2-e62549c37ddf",
    "platform": "windows",
    "tid": "T1021.001",
    "technique": "Remote Desktop Protocol",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs|netflow-enclave-netflow|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.<br /><br />Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).(Citation: TechNet Remote Desktop Services) <br /><br />Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the [Accessibility Features](https://attack.mitre.org/techniques/T1546/008) technique for Persistence.(Citation: Alperovitch Malware)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/555.html",
        "description": "none",
        "external_id": "CAPEC-555"
      },
      {
        "source_name": "TechNet Remote Desktop Services",
        "url": "https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx",
        "description": "Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Alperovitch Malware",
        "url": "http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/",
        "description": "Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--4f9ca633-15c5-463c-9724-bdcd54fde541",
    "platform": "windows",
    "tid": "T1021.002",
    "technique": "SMB/Windows Admin Shares",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs|process-command-line-parameters|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.<br /><br />SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba.<br /><br />Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include `C$`, `ADMIN$`, and `IPC$`. Adversaries may use this technique in conjunction with administrator-level [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely access a networked system over SMB,(Citation: Wikipedia Server Message Block) to interact with systems using remote procedure calls (RPCs),(Citation: TechNet RPC) transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), [Service Execution](https://attack.mitre.org/techniques/T1569/002), and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047). Adversaries can also use NTLM hashes to access administrator shares on systems with [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) and certain configuration and patch levels.(Citation: Microsoft Admin Shares)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/561.html",
        "description": "none",
        "external_id": "CAPEC-561"
      },
      {
        "source_name": "Wikipedia Server Message Block",
        "url": "https://en.wikipedia.org/wiki/Server_Message_Block",
        "description": "Wikipedia. (2017, December 16). Server Message Block. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet RPC",
        "url": "https://technet.microsoft.com/en-us/library/cc787851.aspx",
        "description": "Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Admin Shares",
        "url": "http://support.microsoft.com/kb/314984",
        "description": "Microsoft. (n.d.). How to create and delete hidden or administrative shares on client computers. Retrieved November 20, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Lateral Movement Payne",
        "url": "https://docs.microsoft.com/en-us/archive/blogs/jepayne/tracking-lateral-movement-part-one-special-groups-and-specific-service-accounts",
        "description": "Payne, J. (2015, November 26). Tracking Lateral Movement Part One - Special Groups and Specific Service Accounts. Retrieved February 1, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Windows Event Forwarding Payne",
        "url": "https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem",
        "description": "Payne, J. (2015, November 23). Monitoring what matters - Windows Event Forwarding for everyone (even if you already have a SIEM.). Retrieved February 1, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Medium Detecting WMI Persistence",
        "url": "https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96",
        "description": "French, D. (2018, October 9). Detecting & Removing an Attacker’s WMI Persistence. Retrieved October 11, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--68a0c5ed-bee2-4513-830d-5b0d650139bd",
    "platform": "windows",
    "tid": "T1021.003",
    "technique": "Distributed Component Object Model",
    "tactic": "lateral-movement",
    "datasources": "api-monitoring|authentication-logs|dll-monitoring|packet-capture|powershell-logs|process-monitoring|windows-event-logs|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote machines by taking advantage of Distributed Component Object Model (DCOM). The adversary may then perform actions as the logged-on user.<br /><br />The Windows Component Object Model (COM) is a component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically Dynamic Link Libraries (DLL) or executables (EXE). Distributed COM (DCOM) is transparent middleware that extends the functionality of COM beyond a local computer using remote procedure call (RPC) technology.(Citation: Fireeye Hunting COM June 2019)(Citation: Microsoft COM)<br /><br />Permissions to interact with local and remote server COM objects are specified by access control lists (ACL) in the Registry.(Citation: Microsoft Process Wide Com Keys) By default, only Administrators may remotely activate and launch COM objects through DCOM.(Citation: Microsoft COM ACL)<br /><br />Through DCOM, adversaries operating in the context of an appropriately privileged user can remotely obtain arbitrary and even direct shellcode execution through Office applications(Citation: Enigma Outlook DCOM Lateral Movement Nov 2017) as well as other Windows objects that contain insecure methods.(Citation: Enigma MMC20 COM Jan 2017)(Citation: Enigma DCOM Lateral Movement Jan 2017) DCOM can also execute macros in existing documents(Citation: Enigma Excel DCOM Sept 2017) and may also invoke Dynamic Data Exchange (DDE) execution directly through a COM created instance of a Microsoft Office application(Citation: Cyberreason DCOM DDE Lateral Movement Nov 2017), bypassing the need for a malicious document.<br /><br />",
    "technique_references": [
      {
        "source_name": "Fireeye Hunting COM June 2019",
        "url": "https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html",
        "description": "Hamilton, C. (2019, June 4). Hunting COM Objects. Retrieved June 10, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft COM",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx",
        "description": "Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Process Wide Com Keys",
        "url": "https://msdn.microsoft.com/en-us/library/windows/desktop/ms687317(v=vs.85).aspx",
        "description": "Microsoft. (n.d.). Setting Process-Wide Security Through the Registry. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft COM ACL",
        "url": "https://docs.microsoft.com/en-us/windows/desktop/com/dcom-security-enhancements-in-windows-xp-service-pack-2-and-windows-server-2003-service-pack-1",
        "description": "Microsoft. (n.d.). DCOM Security Enhancements in Windows XP Service Pack 2 and Windows Server 2003 Service Pack 1. Retrieved November 22, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Enigma Outlook DCOM Lateral Movement Nov 2017",
        "url": "https://enigma0x3.net/2017/11/16/lateral-movement-using-outlooks-createobject-method-and-dotnettojscript/",
        "description": "Nelson, M. (2017, November 16). Lateral Movement using Outlook's CreateObject Method and DotNetToJScript. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Enigma MMC20 COM Jan 2017",
        "url": "https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/",
        "description": "Nelson, M. (2017, January 5). Lateral Movement using the MMC20 Application COM Object. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Enigma DCOM Lateral Movement Jan 2017",
        "url": "https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/",
        "description": "Nelson, M. (2017, January 23). Lateral Movement via DCOM: Round 2. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Enigma Excel DCOM Sept 2017",
        "url": "https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/",
        "description": "Nelson, M. (2017, September 11). Lateral Movement using Excel.Application and DCOM. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Cyberreason DCOM DDE Lateral Movement Nov 2017",
        "url": "https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom",
        "description": "Tsukerman, P. (2017, November 8). Leveraging Excel DDE for lateral movement via DCOM. Retrieved November 21, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--2db31dcd-54da-405d-acef-b9129b816ed6",
    "platform": "linux|macos",
    "tid": "T1021.004",
    "technique": "SSH",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs|netflow-enclave-netflow|network-protocol-analysis|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into remote machines using Secure Shell (SSH). The adversary may then perform actions as the logged-on user.<br /><br />SSH is a protocol that allows authorized users to open remote shells on other computers. Many Linux and macOS versions come with SSH installed by default, although typically disabled until the user enables it. The SSH server can be configured to use standard password authentication or public-private keypairs in lieu of or in addition to a password. In this authentication scenario, the user’s public key must be in a special file on the computer running the server that lists which keypairs are allowed to login as that user.(Citation: SSH Secure Shell)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/555.html",
        "description": "none",
        "external_id": "CAPEC-555"
      },
      {
        "source_name": "SSH Secure Shell",
        "url": "https://www.ssh.com/ssh",
        "description": "SSH.COM. (n.d.). SSH (Secure Shell). Retrieved March 23, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--01327cde-66c4-4123-bf34-5f258d59457b",
    "platform": "linux|macos|windows",
    "tid": "T1021.005",
    "technique": "VNC",
    "tactic": "lateral-movement",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely control machines using Virtual Network Computing (VNC). The adversary may then perform actions as the logged-on user.<br /><br />VNC is a desktop sharing system that allows users to remotely control another computer’s display by relaying mouse and keyboard inputs over the network. VNC does not necessarily use standard user credentials. Instead, a VNC client and server may be configured with sets of credentials that are used only for VNC connections.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/555.html",
        "description": "none",
        "external_id": "CAPEC-555"
      }
    ]
  },
  {
    "id": "attack-pattern--60d0c01d-e2bf-49dd-a453-f8a9c9fa6f65",
    "platform": "windows",
    "tid": "T1021.006",
    "technique": "Windows Remote Management",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs|file-monitoring|netflow-enclave-netflow|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.<br /><br />WinRM is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services).(Citation: Microsoft WinRM) It may be called with the `winrm` command or by any number of programs such as PowerShell.(Citation: Jacobsen 2014)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft WinRM",
        "url": "http://msdn.microsoft.com/en-us/library/aa384426",
        "description": "Microsoft. (n.d.). Windows Remote Management. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Jacobsen 2014",
        "url": "https://www.slideshare.net/kieranjacobsen/lateral-movement-with-power-shell-2",
        "description": "Jacobsen, K. (2014, May 16). Lateral Movement with PowerShell&#91;slides&#93;. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Medium Detecting Lateral Movement",
        "url": "https://medium.com/threatpunter/detecting-lateral-movement-using-sysmon-and-splunk-318d3be141bc",
        "description": "French, D. (2018, September 30). Detecting Lateral Movement Using Sysmon and Splunk. Retrieved October 11, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f005e783-57d4-4837-88ad-dbe7faee1c51",
    "platform": "office-365|saas",
    "tid": "T1550.001",
    "technique": "Application Access Token",
    "tactic": "lateral-movement",
    "datasources": "oauth-audit-logs|office-365-audit-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users and used in lieu of login credentials.<br /><br />Application access tokens are used to make authorized API requests on behalf of a user and are commonly used as a way to access resources in cloud-based applications and software-as-a-service (SaaS).(Citation: Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019) OAuth is one commonly implemented framework that issues tokens to users for access to systems. These frameworks are used collaboratively to verify the user and determine what actions the user is allowed to perform. Once identity is established, the token allows actions to be authorized, without passing the actual credentials of the user. Therefore, compromise of the token can grant the adversary access to resources of other sites through a malicious application.(Citation: okta)<br /><br />For example, with a cloud-based email service once an OAuth access token is granted to a malicious application, it can potentially gain long-term access to features of the user account if a \"refresh\" token enabling background access is awarded.(Citation: Microsoft Identity Platform Access 2019) With an OAuth access token an adversary can use the user-granted REST API to perform functions such as email searching and contact enumeration.(Citation: Staaldraad Phishing with OAuth 2017)<br /><br />Compromised access tokens may be used as an initial step in compromising other services. For example, if a token grants access to a victim’s primary email, the adversary may be able to extend access to all other services which the target subscribes by triggering forgotten password routines. Direct API access through a token negates the effectiveness of a second authentication factor and may be immune to intuitive countermeasures like changing passwords. Access abuse over an API channel can be difficult to detect even from the service provider end, as the access can still align well with a legitimate workflow.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/593.html",
        "description": "none",
        "external_id": "CAPEC-593"
      },
      {
        "source_name": "Auth0 - Why You Should Always Use Access Tokens to Secure APIs Sept 2019",
        "url": "https://auth0.com/blog/why-should-use-accesstokens-to-secure-an-api/",
        "description": "Auth0. (n.d.). Why You Should Always Use Access Tokens to Secure APIs. Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "okta",
        "url": "https://developer.okta.com/blog/2018/06/20/what-happens-if-your-jwt-is-stolen",
        "description": "okta. (n.d.). What Happens If Your JWT Is Stolen?. Retrieved September 12, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Identity Platform Access 2019",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens",
        "description": "Cai, S., Flores, J., de Guzman, C., et. al.. (2019, August 27). Microsoft identity platform access tokens. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Staaldraad Phishing with OAuth 2017",
        "url": "https://staaldraad.github.io/2017/08/02/o356-phishing-with-oauth/",
        "description": "Stalmans, E.. (2017, August 2). Phishing with OAuth and o365/Azure. Retrieved October 4, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e624264c-033a-424d-9fd7-fc9c3bbdb03e",
    "platform": "windows",
    "tid": "T1550.002",
    "technique": "Pass the Hash",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.<br /><br />Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.(Citation: NSA Spotting)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/644.html",
        "description": "none",
        "external_id": "CAPEC-644"
      },
      {
        "source_name": "NSA Spotting",
        "url": "https://apps.nsa.gov/iaarchive/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm",
        "description": "National Security Agency/Central Security Service Information Assurance Directorate. (2015, August 7). Spotting the Adversary with Windows Event Log Monitoring. Retrieved September 6, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7b211ac6-c815-4189-93a9-ab415deca926",
    "platform": "windows",
    "tid": "T1550.003",
    "technique": "Pass the Ticket",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may “pass the ticket” using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.<br /><br />In this technique, valid Kerberos tickets for [Valid Accounts](https://attack.mitre.org/techniques/T1078) are captured by [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). A user's service tickets or ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access.(Citation: ADSecurity AD Kerberos Attacks)(Citation: GentilKiwi Pass the Ticket)<br /><br />[Silver Ticket](https://attack.mitre.org/techniques/T1558/002) can be obtained for services that use Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint).(Citation: ADSecurity AD Kerberos Attacks)<br /><br />[Golden Ticket](https://attack.mitre.org/techniques/T1558/001) can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active Directory.(Citation: Campbell 2014)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/645.html",
        "description": "none",
        "external_id": "CAPEC-645"
      },
      {
        "source_name": "ADSecurity AD Kerberos Attacks",
        "url": "https://adsecurity.org/?p=556",
        "description": "Metcalf, S. (2014, November 22). Mimikatz and Active Directory Kerberos Attacks. Retrieved June 2, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "GentilKiwi Pass the Ticket",
        "url": "http://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos",
        "description": "Deply, B. (2014, January 13). Pass the ticket. Retrieved June 2, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Campbell 2014",
        "url": "http://defcon.org/images/defcon-22/dc-22-presentations/Campbell/DEFCON-22-Christopher-Campbell-The-Secret-Life-of-Krbtgt.pdf",
        "description": "Campbell, C. (2014). The Secret Life of Krbtgt. Retrieved December 4, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "CERT-EU Golden Ticket Protection",
        "url": "https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf",
        "description": "Abolins, D., Boldea, C., Socha, K., Soria-Machado, M. (2016, April 26). Kerberos Golden Ticket Protection. Retrieved July 13, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--c3c8c916-2f3c-4e71-94b2-240bdfc996f0",
    "platform": "office-365|saas",
    "tid": "T1550.004",
    "technique": "Web Session Cookie",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs|office-365-audit-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated.(Citation: Pass The Cookie)<br /><br />Authentication cookies are commonly used in web applications, including cloud-based services, after a user has authenticated to the service so credentials are not passed and re-authentication does not need to occur as frequently. Cookies are often valid for an extended period of time, even if the web application is not actively used. After the cookie is obtained through [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539), the adversary may then import the cookie into a browser they control and is then able to use the site or application as the user for as long as the session cookie is active. Once logged into the site, an adversary can access sensitive information, read email, or perform actions that the victim account has permissions to perform.<br /><br />There have been examples of malware targeting session cookies to bypass multi-factor authentication systems.(Citation: Unit 42 Mac Crypto Cookies January 2019)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/60.html",
        "description": "none",
        "external_id": "CAPEC-60"
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
        "description": "Chen, Y., Hu, W., Xu, Z., et. al.. (2019, January 31). Mac Malware Steals Cryptocurrency Exchanges’ Cookies. Retrieved October 14, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--4d2a5b3e-340d-4600-9123-309dd63c9bf8",
    "platform": "linux|macos",
    "tid": "T1563.001",
    "technique": "SSH Hijacking",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair.<br /><br />In order to move laterally from a compromised host, adversaries may take advantage of trust relationships established with other systems via public key authentication in active SSH sessions by hijacking an existing connection to another system. This may occur through compromising the SSH agent itself or by having access to the agent's socket. If an adversary is able to obtain root access, then hijacking SSH sessions is likely trivial.(Citation: Slideshare Abusing SSH)(Citation: SSHjack Blackhat)(Citation: Clockwork SSH Agent Hijacking)(Citation: Breach Post-mortem SSH Hijack)<br /><br />[SSH Hijacking](https://attack.mitre.org/techniques/T1563/001) differs from use of [SSH](https://attack.mitre.org/techniques/T1021/004) because it hijacks an existing SSH session rather than creating a new session using [Valid Accounts](https://attack.mitre.org/techniques/T1078).<br /><br />",
    "technique_references": [
      {
        "source_name": "Slideshare Abusing SSH",
        "url": "https://www.slideshare.net/morisson/mistrusting-and-abusing-ssh-13526219",
        "description": "Duarte, H., Morrison, B. (2012). (Mis)trusting and (ab)using ssh. Retrieved January 8, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "SSHjack Blackhat",
        "url": "https://www.blackhat.com/presentations/bh-usa-05/bh-us-05-boileau.pdf",
        "description": "Adam Boileau. (2005, August 5). Trust Transience:  Post Intrusion SSH Hijacking. Retrieved December 19, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Clockwork SSH Agent Hijacking",
        "url": "https://www.clockwork.com/news/2012/09/28/602/ssh_agent_hijacking",
        "description": "Beuchler, B. (2012, September 28). SSH Agent Hijacking. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Breach Post-mortem SSH Hijack",
        "url": "https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident",
        "description": "Hodgson, M. (2019, May 8). Post-mortem and remediations for Apr 11 security incident. Retrieved February 17, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e0033c16-a07e-48aa-8204-7c3ca669998c",
    "platform": "windows",
    "tid": "T1563.002",
    "technique": "RDP Hijacking",
    "tactic": "lateral-movement",
    "datasources": "authentication-logs|netflow-enclave-netflow|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).(Citation: TechNet Remote Desktop Services)<br /><br />Adversaries may perform RDP session hijacking which involves stealing a legitimate user's remote session. Typically, a user is notified when someone else is trying to steal their session. With System permissions and using Terminal Services Console, `c:\\windows\\system32\\tscon.exe [session number to be stolen]`, an adversary can hijack a session without the need for credentials or prompts to the user.(Citation: RDP Hijacking Korznikov) This can be done remotely or locally and with active or disconnected sessions.(Citation: RDP Hijacking Medium) It can also lead to [Remote System Discovery](https://attack.mitre.org/techniques/T1018) and Privilege Escalation by stealing a Domain Admin or higher privileged account session. All of this can be done by using native Windows commands, but it has also been added as a feature in red teaming tools.(Citation: Kali Redsnarf)<br /><br />",
    "technique_references": [
      {
        "source_name": "TechNet Remote Desktop Services",
        "url": "https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx",
        "description": "Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "RDP Hijacking Korznikov",
        "url": "http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html",
        "description": "Korznikov, A. (2017, March 17). Passwordless RDP Session Hijacking Feature All Windows versions. Retrieved December 11, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "RDP Hijacking Medium",
        "url": "https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6",
        "description": "Beaumont, K. (2017, March 19). RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation. Retrieved December 11, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Kali Redsnarf",
        "url": "https://github.com/nccgroup/redsnarf",
        "description": "NCC Group PLC. (2016, November 1). Kali Redsnarf. Retrieved December 11, 2017.",
        "external_id": "none"
      }
    ]
  }
]
