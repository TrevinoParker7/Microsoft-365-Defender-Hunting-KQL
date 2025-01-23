### 🔥 **KQL Advanced Hunting**    
🎯 **Topic**: **Let’s Hunt! Applying KQL to Incident Tracking**  
🎤 **Presenter**: **Trevino Parker**    

---

### 📚 **Schema Reference**  
(📍Located in the **upper right corner got alot of good stuff in there** 🔗)  

---

### 🌟 **The ABC's of Security**  

🔑 **Authentication**  
- How is the attacker establishing identity to the system? 🤔  
- What identities do we consider compromised? 🚨  
- What are our administrative identities? 👨‍💻  

🛠️ **Backdoors**  
- How is the attacker controlling the system? 🎛️  
- Is the service used by the attacker legitimate or illegitimate? ⚖️  
- Where is this capability or condition present? 📍  

📡 **Communication**  
- How is the attacker communicating with the system? 📞  

---

### 🧙‍♂️ **Let’s See What the Malware Fairy Has Brought Us Today...** 🪄  

#### **Inspect Alert Information** 📊  
```kql
AlertInfo 
| take 10
```
💡 **Description**: The **AlertInfo** table contains alerts identified by MTP.  
⚠️ **Note**: To retrieve entities and evidence associated with an alert, use the **AlertEvidence** table.  

#### **Inspect Alert Evidence** 🔍  
```kql
AlertEvidence 
| take 10
```
💡 **Description**: The **AlertEvidence** table provides details about alerts, including associated entities.  

---

### 🧩 **Let’s Find Out Which of Our Accounts Has the Most Alerts Associated with Them!** 👀  
```kql
AlertEvidence 
| where Timestamp > ago(19d) and EntityType == "User" and isnotempty(AccountObjectId) // Look for user entities 
| summarize Alerts = dcount(AlertId) by AccountObjectId, AccountName, AccountDomain 
| project Alerts, AccountDomain, AccountName, AccountObjectId 
| order by Alerts desc
```

---

### 🔎 **That’s Suspicious... Let’s See What Kinds of Alerts These Are!** 🚩  
```kql
AlertEvidence 
| where Timestamp > ago(19d) and EntityType == "User" and AccountObjectId == 'ab653b2a-d23e-49df-9493-c26590f8f319' 
| join kind=inner AlertInfo on AlertId 
| summarize Alerts = count(), First = min(Timestamp), Last = max(Timestamp) by Title 
| order by Alerts desc
```

---

### 🕵️ **That Doesn’t Look Good. Let’s Find Out When and Where This Happened!** 🗺️  
```kql
AlertEvidence 
| where Timestamp > ago(19d) and AccountObjectId == 'ab653b2a-d23e-49df-9493-c26590f8f319' // Associated with the suspicious account 
| join kind=rightsemi AlertEvidence on AlertId // Rejoin with evidence... 
| where EntityType == 'Machine' // And get the machines. 
| join kind=leftouter ( 
    DeviceInfo 
    | summarize DeviceName = any(DeviceName) by DeviceId // Get the device name 
) on DeviceId 
| summarize dcount(AlertId) by DeviceName, bin(Timestamp, 1d) // Plot it in daily intervals 
| render timechart // Make a timechart
```

📊 **Observation**:  
- 🖥️ Looks like the activity started on **barbaram-pc**!  
- 📆 There’s an uptick in activity on **July 19th**.  

---

### ⏳ **Let’s Timeline Alerts on barbaram-pc** 🕰️  
```kql
AlertEvidence 
| where Timestamp > ago(19d) and DeviceId == '87da11a9257988b2fc090c9f05c72f6453bc53de' 
| join kind=inner AlertInfo on AlertId 
| summarize min(Timestamp) by Title 
| order by min_Timestamp asc
```

---

### 🚨 **Detected Something Malicious From Office 365. Let’s Investigate!**  
```kql
AlertInfo 
| where Timestamp > ago(19d) and Title == 'Post-delivery detection of suspicious attachment' 
| join kind=rightsemi AlertEvidence on AlertId 
| where EntityType == 'File'
```

---

### 🛠️ **Let’s Turn JSON into a Table for Better Insights** 📑  
```kql
AlertInfo 
| where Timestamp > ago(19d) and Title == 'Post-delivery detection of suspicious attachment' 
| join kind=rightsemi AlertEvidence on AlertId 
| where EntityType == 'File' 
| extend AFDynamic = parse_json(AdditionalFields) // Turn JSON into a dynamic column 
| evaluate bag_unpack(AFDynamic) // ...and turn the JSON into columns 
| project-reorder Name, Directory, Host, SHA256
```

💡 **Functions Used**:  
- **parse_json()**: Parses a JSON string and converts it into a dynamic object.  
- **bag_unpack()**: Promotes the first-level properties of a dynamic object to columns.  

--- 

### **🚨 Analyzing Malicious Attachments**  
👩‍💻 File: **Doodles_SOW_07102020.doc**  
```kql
DeviceProcessEvents
| where Timestamp > ago(19d)
and ProcessCommandLine contains 'UpdatedPolicy_SOW_07182020.doc'
and AccountObjectId == 'ab653b2a-d23e-49df-9493-c26590f8f319'
```

### **🧑‍💻 Deep Dive: Barbara's Actions**  
🔍 Registry and network activity linked to **PID 13988**:  
```kql
search in (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceEvents)
| where Timestamp > ago(19d) and DeviceId == '87da11a9257988b2fc090c9f05c72f6453bc53de' and InitiatingProcessId == 13988
| where RegistryKey !contains @'\Software\Microsoft\Office\16.0\Common\Internet\Server Cache'
| order by Timestamp asc
| project-reorder Timestamp, $table, ActionType, RemoteIP, RemoteUrl, FileName, SHA256, RegistryKey, RegistryValueData
```

---

### **📡 SharePoint Activity**  
Let’s find out how the suspicious document reached SharePoint:  
```kql
AppFileEvents
| where Timestamp > ago(19d) and FileName =~ 'UpdatedPolicy_SOW_07182020.doc'
| project-reorder Timestamp, ActionType, Application, FolderPath, IPAddress, Location, ISP
| order by Timestamp asc
```
### 🚨 **Investigating Suspicious IPs** 🔍

```kql
// Looks like we have a couple strange IPs interacting with the file: 
// 178.32.124.142 and 51.83.139.56. 
// It was uploaded using **Barbara's account** – that's the **Authentication** 
// The "backdoor" is just a publicly available service (**SharePoint**) 
// The **Communication** channel involves those IPs. Let's see what else was involved with them... 🌐

search Timestamp > ago(19d) and ('178.32.124.142' or '51.83.139.56')
| project-reorder $table, Timestamp, AccountName, AccountDomain, ActionType, FileName, FolderPath 
```

### 🧐 **Key Observations:**
- **IP Investigation** 🌍: We're focusing on the two IPs, `178.32.124.142` and `51.83.139.56`.
- **Authentication** 🔐: Barbara's account was used in this interaction.
- **Backdoor** 🔑: The malicious "backdoor" was just a publicly accessible service (**SharePoint**).
- **Communication** 📡: Both suspicious IPs were communicating with the environment.

---

🚨 Strange IPs detected: **178.32.124.142**, **51.83.139.56**  
🛠️ Investigate additional documents uploaded from the same user.

---

### **🔗 Tor Connections and Credential Theft**  
Analyzing suspicious IPs and correlating alerts:  
```kql
AlertEvidence
| where RemoteIP in ('178.32.124.142', '51.83.139.56')
| join kind=rightsemi AlertInfo on AlertId
```

---

### **🛡️ Logon Analysis**  
🖥️ **Compromised Device**: **barbaram-pc.mtpdemos.net**  
```kql
DeviceLogonEvents 
| where DeviceName == 'barbaram-pc.mtpdemos.net' and Timestamp > ago(19d) and ActionType == 'LogonSuccess'
| where AccountDomain !in ('font driver host', 'window manager')
| extend Account = strcat(AccountDomain, '\\', AccountName)
| summarize count() by Account, bin(Timestamp, 1h)
| render timechart
```

---

### **🧑‍💼 Investigating Eric Gubbels**  
Role: **Help Desk Supervisor**  
Potentially elevated permissions. Exploring his activity:  
```kql
IdentityLogonEvents
| where Timestamp > todatetime('2020-07-17') and AccountObjectId == '993788dd-7c13-4db8-9b0a-6297fcb8d5b3'
| summarize count() by DeviceName, bin(Timestamp, 1d)
| render timechart
---

### 🚨 **Ok, what alerts do we have with his account?** 🤔

```kql
let EricGAlerts = ( 
    AlertEvidence 
    | where Timestamp > todatetime('2020-07-17') and AccountObjectId == '993788dd-7c13-4db8-9b0a-6297fcb8d5b3'
); // Get all alerts for EricG's account 
EricGAlerts 
| join kind=rightsemi AlertInfo on AlertId // Get the alert info 🔍
| join AlertEvidence on AlertId // Join back on AlertEvidence to get other evidence 📝
| join kind = leftouter ( 
    DeviceInfo 
    | summarize DeviceName = any(DeviceName) by DeviceId
) on DeviceId // Mapping DeviceId and DeviceName 📱
| extend DomainAndAccount = strcat(AccountDomain, '\\', AccountName) 
| summarize Timestamp = min(Timestamp) 
, Device = make_set_if(DeviceName, isnotempty(DeviceName)) 
, SHA1 = make_set_if(SHA1,isnotempty(SHA1)) 
, SHA256 = make_set_if(SHA256, isnotempty(SHA256)) 
, RemoteIP = make_set_if(RemoteIP, isnotempty(RemoteIP)) 
, RemoteUrl = make_set_if(RemoteUrl, isnotempty(RemoteUrl)) 
, Account = make_set_if(DomainAndAccount, DomainAndAccount != '\\') by AlertId, Title // Build a nice JSON report 📊
| order by Timestamp asc 
```

### 🧐 **Analyzing the Alerts...**

- We have some **interesting things** here! 👀 
    - A **new device of interest** 🖥️ - **robertot-pc** 
    - Attacker might have created a **malicious inbox forwarding rule** 🔑 (backdoor) set from **52.137.127.6** (communication) 💬 
    - Evidence of a **possible skeleton key attack** 🛡️ (Authentication) 
    - A few **logons using potentially stolen credentials** 🔓 [mtp-air-aadconnect01 and mtp-air-dc01] (Authentication) 
    - I wonder if that **IP address** is one of our devices... 🤔

### 🌐 **Let's Check the IP!** 📍

```kql
DeviceInfo 
| where PublicIP == "52.137.127.6" 
| distinct DeviceName 
```

- **Bingo!** 🎯 Back to **barbaram-pc**. Yup, we'll have to queue that up for investigation. ✅

### 📄 **Let's Look for That Other Word Doc...** 📑

```kql
DeviceFileEvents 
| where Timestamp > ago(19d) and FileName =~ "BYODRegistration (1).docm" 
| summarize count() by SHA1, SHA256, MD5
```

- Got our file hash! 🕵️‍♂️ Let's see what the world knows about it 🌍

### 🕵️‍♀️ **Investigating the File Hash...**

```kql
DeviceFileEvents 
| where SHA256 == 'c18732c861641a5a91d1578efad6f1a2546dc4bd97c68a5f6a6ba5d4f5d76242' 
| take 1 
| invoke FileProfile() // Note you need the SHA1 for this to work 🛠️
| project-reorder GlobalPrevalence, GlobalFirstSeen, GlobalLastSeen , Signer, Issuer, SignerHash, IsCertificateValid, IsRootSignerMicrosoft, IsExecutable, ThreatName, Publisher, SoftwareName
```

- **Low prevalence**, **first seen** in **April of 2020**. Might be targeted, but it's a **Word doc**, so global prevalence might be misleading... 🤔

---

### 🛑 **Taking Action – Malicious File Quarantine!** ⚠️

```kql
DeviceFileEvents 
| where SHA256 == 'c18732c861641a5a91d1578efad6f1a2546dc4bd97c68a5f6a6ba5d4f5d76242'
```

- It's clear this file is **malicious** 🚫, we don’t want it in our environment. Let's **quarantine** it 🛑

---

### 🔍 **Custom Detection Rule for Future Alerts!** 🧠

We found several **IOCs** during this investigation 🔎, like **IPs** and **file hashes**. We need to **create a custom detection rule** 🔔 to ensure we get alerted on future activity involving these IOCs.

```kql
search in (DeviceNetworkEvents, DeviceEvents) 
RemoteIP in ('178.32.124.142', '51.83.139.56') or FileOriginIP  in ('178.32.124.142', '51.83.139.56') or IPAddress in ('178.32.124.142', '51.83.139.56')
```

- **Detection name** – Activity involving malicious IP (`178.32.124.142`, `51.83.139.56`) 🚨
- **Alert title** – Activity involving malicious IP 🚨
- **Category** – Suspicious activity 🚩
- **MITRE techniques** - (Will need to apply based on the technique analysis)
- **Description** – Activity with `178.32.124.142`, `51.83.139.56` observed 🌐

---

### 👣 **Go Hunt!** 🏹

🔍 The investigation continues with a keen eye on IOCs, malicious behavior, and a deep dive into the associated activity! 💥 **Hunt the threat** and stay proactive! 🔒

---

