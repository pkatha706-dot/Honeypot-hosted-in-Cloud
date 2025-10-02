# Honeypot Hosted in Azure 

## Objective

This project demonstrates the deployment and configuration of a multi-honeypot environment using T-Pot on Microsoft Azure. The primary goal was to capture and analyze real-world cyber attacks by exposing a controlled vulnerable system to the internet. This hands-on project provides practical experience in threat intelligence gathering, attack pattern analysis, and cloud security architecture while utilizing industry-standard tools for log aggregation and visualization.

### Skills Learned

- Cloud infrastructure deployment and configuration in Microsoft Azure
- Linux system administration and security hardening
- Honeypot implementation and management using T-Pot framework
- Network security configuration including firewall rules and port management
- Real-time threat detection and attack surface monitoring
- Log analysis and correlation using ELK Stack (Elasticsearch, Logstash, Kibana)
- OSINT (Open Source Intelligence) gathering and threat actor profiling
- Data visualization and dashboard creation for security metrics
- Understanding of global attack patterns and threat actor behavior
- Critical analysis of CVE exploitation attempts in real-world scenarios


### Tools Used

- Microsoft Azure - Cloud platform for hosting the honeypot infrastructure
- Ubuntu Linux Virtual Machine - Base operating system for honeypot deployment
- T-Pot - Multi-honeypot platform integrating 20+ honeypot types
- PuTTY - SSH client for secure remote access to Azure VM
- ELK Stack (Elasticsearch, Kibana) - Log ingestion, storage, and visualization
- Attack Map - Real-time geographic visualization of incoming attacks
- Elasticvue - Elasticsearch cluster monitoring and server health status
- Spiderfoot - OSINT automation tool for attacker IP reconnaissance
- **Multiple Honeypot Services** - Various honeypots simulating vulnerable services (SSH, HTTP, databases, etc.)

## Steps

1. Azure Virtual Machine Creation
   <img width="1979" height="1282" alt="step 1" src="https://github.com/user-attachments/assets/6a00157d-07af-4143-a3ac-400c340a393e" />

   Created a Linux-based Virtual Machine in Azure with appropriate specifications to host the T-Pot honeypot environment. Selected Ubuntu as the operating system for compatibility with T-Pot requirements.
   

3. Network Security Group Configuration
   <img width="1413" height="291" alt="Step 2" src="https://github.com/user-attachments/assets/6ae2694f-87ee-46bf-a698-27c82ac76c25" />

   Configured an extremely permissive inbound security rule to intentionally expose the VM to all internet traffic:
   - Destination Port Ranges**: 0-65535 (all ports)
   - Source: Any
   - Destination: Any
   - Protocol: All

   
5. SSH Connection via PuTTY
   
   <img width="585" height="538" alt="Screenshot (38)" src="https://github.com/user-attachments/assets/ffc33043-3eea-4212-8444-6e3bb5c1cf4e" />


   Established secure SSH connection to the Azure VM using PuTTY to perform initial system configuration and T-Pot installation.

   
7. System Update and Preparation
   Updated the Ubuntu system to ensure all packages were current before honeypot installation:
   - sudo apt update
   - sudo apt upgrade -y

   
9. T-Pot Installation
   Downloaded and installed T-Pot honeypot framework from the official GitHub repository. Configured installation parameters including administrator credentials for web interface access.

   
11. T-Pot Web Interface Access
   <img width="2551" height="1283" alt="Screenshot (64)" src="https://github.com/user-attachments/assets/7deafe76-ae46-4caa-9332-cb0cd22e9cc8" />

   Successfully accessed the T-Pot web interface through the VM's public IP address on port 64297. The interface provides centralized access to all honeypot data and analysis tools.
12. Attack Map Visualization
    <img width="2522" height="1344" alt="Screenshot (65)" src="https://github.com/user-attachments/assets/e1f640ec-8807-43db-936f-27f4756b233a" />

   - The Attack Map provides real-time geographic visualization of incoming attacks, displaying:
   - Source countries of attack traffic
   - Attack intensity and frequency
   - Targeted services and protocols
   - Live connection attempts from threat actors worldwide

13. Elasticvue Server Monitoring
    <img width="2563" height="1350" alt="Screenshot (66)" src="https://github.com/user-attachments/assets/db28ef8f-403b-4d15-bf2a-1794e216987d" />

    Elasticvue dashboard showing cluster health and statistics

   <img width="2558" height="752" alt="Screenshot (67)" src="https://github.com/user-attachments/assets/0b7ad0f1-671c-4e1d-b183-a79d8af72351" />
 
   Monitored the Elasticsearch cluster health and performance metrics using Elasticvue, including:

   - Server resource utilization
   - Data ingestion rates
   - Index statistics and storage usage
   - Cluster node status

11. Kibana Dashboard Analysis
   <img width="2558" height="1354" alt="Screenshot (72)" src="https://github.com/user-attachments/assets/f2107010-365d-4871-a89f-15027f7b3b6e" />


   Kibana dashboard showing attack statistics by honeypot type
   Analyzed collected data through Kibana dashboards, revealing:

   - Attacks by Honeypot: Distribution of attacks across different honeypot services
   - Top Targeted Services: Most commonly attacked protocols (SSH, HTTP, Telnet, etc.)
   - Attack Trends Over Time: Temporal patterns in malicious activity
   - Geographic Distribution: Countries generating the most attack traffic

11. CVE Exploit Tracking
    
    <img width="2562" height="1348" alt="Screenshot (71)" src="https://github.com/user-attachments/assets/3913e016-2f16-4d39-ac02-440ba7e8d39e" />

    Dashboard showing CVE details of attempted exploits
    <img width="2566" height="1341" alt="Screenshot (74)" src="https://github.com/user-attachments/assets/253b3ce8-875d-4546-a3da-08aaf145aa15" />

    Identified specific CVE (Common Vulnerabilities and Exposures) exploitation attempts, providing insight into:
    
    - Active vulnerability exploitation in the wild
    - Threat actor tactics and techniques
    - Prevalence of known exploits
    - Zero-day vs. known vulnerability targeting

13. Spiderfoot OSINT Investigation
    <img width="2555" height="1357" alt="Screenshot (73)" src="https://github.com/user-attachments/assets/2396a290-1b25-4956-8877-9c8b8a7cbb24" />

     Spiderfoot results showing attacker IP analysis
    Utilized Spiderfoot for comprehensive reconnaissance of attacker IP addresses, gathering:
    
    - ISP (Internet Service Provider) information
    - Associated domains and hostnames
    - Geolocation data
    - Historical threat intelligence
    - Related infrastructure and network details
    - Potential attribution indicators

### Key Findings
 
###
