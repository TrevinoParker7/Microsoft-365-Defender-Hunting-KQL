
### 🎯 **Tracking the Adversary with MTP Advanced Hunting**  
**Series:** `Advanced Hunting`  
**Topic:** `Let’s Hunt! Applying KQL to Incident Tracking`  
---

#### 🚨 **The ABCs of Security**  
🔒 **Authentication**  
- 🕵️‍♂️ *How is the attacker establishing identity to the system?*  
- ❓ *What identities do we consider compromised?*  
- 👩‍💻 *What are our administrative identities?*  

🛠️ **Backdoors**  
- 🔍 *How is the attacker controlling the system?*  
- 🛑 *Is the service used by the attacker legitimate or illegitimate?*  
- 📍 *Where is this capability or condition present?*  

💬 **Communication**  
- 🔗 *How is the attacker communicating with the system?*  

📜 **Let’s see what the malware fairy 🧚‍♀️ brought us today...**

---

### 🔎 **Alert Insights**  

📊 **Get Alerts Overview:**  
```kql
AlertInfo 
| take 10
```  
📝 **Description:** Contains alerts identified by MTP but lacks entities and evidence. Use `AlertEvidence` to dive deeper.  

📊 **Dig Deeper with Evidence:**  
```kql
AlertEvidence 
| take 10
```  
📝 **Description:** Provides details about alerts, including associated entities.  

---

### 📌 **Identify Accounts with Most Alerts**  
```kql
AlertEvidence 
| where Timestamp > ago(19d) and EntityType == "User" and isnotempty(AccountObjectId) 
| summarize Alerts = dcount(AlertId) by AccountObjectId, AccountName, AccountDomain 
| project Alerts, AccountDomain, AccountName, AccountObjectId 
| order by Alerts desc
```  

---

### ❗ **Dive Into Suspicious Activity**  
- 🕵️ Suspicious account: `ab653b2a-d23e-49df-9493-c26590f8f319`  
- 🔍 Alerts grouped by type:  
```kql
AlertEvidence 
| where Timestamp > ago(19d) and EntityType == "User" and AccountObjectId == 'ab653b2a-d23e-49df-9493-c26590f8f319' 
| join kind=inner AlertInfo on AlertId 
| summarize Alerts = count(), First = min(Timestamp), Last = max(Timestamp) by Title 
| order by Alerts desc
```  

🖥️ **Track Device Activity:**  
```kql
AlertEvidence 
| where Timestamp > ago(19d) and AccountObjectId == 'ab653b2a-d23e-49df-9493-c26590f8f319'
| where EntityType == 'Machine' 
| summarize dcount(AlertId) by DeviceName, bin(Timestamp, 1d) 
| render timechart
```  

📌 **Key Device:** `barbaram-pc`  
🗓️ **Spike in activity:** `July 19th`  

---

### 📂 **File Suspicious Activity Analysis**  
- 📝 File: `Doodles_SOW_07102020.doc`  

```kql
AlertInfo 
| where Timestamp > ago(19d) and Title == 'Post-delivery detection of suspicious attachment' 
| join kind=rightsemi AlertEvidence on AlertId 
| where EntityType == 'File' 
| extend AFDynamic = parse_json(AdditionalFields)
| evaluate bag_unpack(AFDynamic) 
| project-reorder Name, Directory, Host, SHA256
```  

---

### 🌍 **Suspicious IPs Identified**  
- **IPs:** `178.32.124.142`, `51.83.139.56`  
- **Channel:** SharePoint (legitimate backdoor).  

---

### 🔗 **Eric Gubbels' Activity**  
🕵️‍♂️ **Identity Details:**  
```kql
IdentityInfo 
| where GivenName =~ 'Eric' and Surname =~ "Gubbels" 
| take 1
```  
🛠️ **Role:** Help Desk Supervisor (Elevated Permissions).  

---

### 🗂️ **Summary of Findings**  
📌 **Key Devices:** `barbaram-pc`, `robertot-pc`.  
🚩 **Malicious Indicators:**  
- Credential theft.  
- Skeleton key attack.  
- Suspicious inbox forwarding rules.  

🎯 **Next Steps:** Investigate further and isolate compromised accounts, devices, and IPs.

---

