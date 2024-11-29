# Method of Analysis Playbook  

## General Overview  

### **1. Network Analysis – Surveying Stone Deposits** 
 
- Begin by identifying compromised systems through network artifacts, such as unusual traffic patterns or unauthorized connections.  

- Think of this as locating the initial block of marble for your investigation. Network analysis provides a broad view of activity, helping pinpoint suspicious behavior worth deeper exploration.  

### **2. Isolating Systems and Capturing Volatile Data – Shaping the Block (1/3)** 
 
- Focus on volatile data (e.g., memory, live network activity) early to prevent critical evidence from being lost. 
 
- In cases involving a **Determined Human Adversary (DHA)**, consider delaying isolation to monitor their **Tactics, Techniques, and Procedures (TTPs)** and gain additional intelligence.  

### **3. Event Log Collection – Shaping the Block (2/3)**  

- Event logs provide a timeline of system activity and attacker movements. Focus on **Event IDs (EIDs)** and their surrounding context to identify patterns efficiently.  

### **4. Disk Artifact Analysis – Shaping the Block (3/3)**  

- Examine artifacts such as prefetch files, shim cache, and the App Compatibility Cache to uncover executed applications and attacker interactions with the system. 

### **5. Forensic Analysis – Chiseling the Details**  

- Conduct deeper forensic analysis to map out how the attacker gained access, what tools they used, and their movements through the environment.  

---

## Collection Order  

Prioritize the **most volatile** data first to capture evidence likely to be altered or lost:  

1. **Memory Collection**  
   - Tools: WinPMEM, F-Response  

2. **Log Collection**  
   - Includes network, event, host, and Windows Defender logs.  
   - Tools: Kansa, KAPE, Velociraptor  

3. **Disk Artifact Collection**  
   - Prefetch, shim cache, AppCompatibility cache, etc.  
   - Tools: Eric Zimmerman’s suite, Autopsy, FTK Imager
  
4. **File System Changes**  
   - Identify malware or persistence mechanisms.  
   - Tools: **UPDATE WITH PERSONAL NOTES** 

---

## Analysis Order  

Analysis is often performed in reverse of collection order, starting with low-effort artifacts to confirm suspicions before diving deeper:  

1. **Log Analysis**  
   - Focus on quick wins by analyzing event and network logs for patterns.  
   - Tools: EvtxECmd, Event Log Explorer, Timeline Explorer.  

2. **Disk Artifact Analysis**  
   - Examine artifacts for evidence of executed commands and attacker activities.  
   - Tools: AppCompatParser.py, Eric Zimmerman’s tools.  

3. **Memory Analysis**  
   - Perform detailed memory analysis to uncover persistence, tools used, and attacker behavior.  
   - Tools: Volatility, MemProcFS, MemoryBaseliner.py  

---
