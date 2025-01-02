# SIEM-Home-Lab

# Objective
This SIEM Lab project aimed to deploy and configure Wazuh as a Security Information and Event Management (SIEM) solution. This involved setting up the Wazuh server on DigitalOcean with secure firewalls, using Sysmon to collect telemetry from a Windows host, and detecting advanced threats such as Mimikatz execution. The primary goal was to establish a functional SIEM environment for log analysis, security monitoring, and threat detection.

# Skills Learned
- Deploying SIEM solutions on cloud platforms.
- Configuring telemetry collection from Windows hosts using Sysmon.
- Analyzing logs and events in a SIEM interface.
- Implementing secure network configurations modifying firewall rules.
- Configured custom detection rules in Wazuh.
- Detected advanced threats like Mimikatz execution.
- Set up and verified accurate alerting systems.

# Lab Setup

## **Tools and Technologies:**
- **SIEM Solution:** Wazuh
- **Operating Systems:**
  - Windows 10 (Telemetry Source)
  - Ubuntu 20.04 (Wazuh Server)
- **Cloud Platform:** DigitalOcean
- **Network Configuration:**
  - Firewalls configured to restrict unauthorized access.

### **Pre-Requisites:**
- A DigitalOcean droplet with Ubuntu 20.04.
- SSH access to the droplet.
- Sysmon installed on the Windows host for telemetry.

---

## **Implementation Steps**

### **Step 1: Deploy Wazuh on DigitalOcean**
1. Create an Ubuntu 20.04 droplet on DigitalOcean.
2. Access the droplet via SSH:
   ```bash
   ssh root@<server-ip>
   ```
3. Install the Wazuh server by following the [official Wazuh documentation](https://documentation.wazuh.com/).
4. Configure firewalls to allow traffic on necessary ports (allow inbound tcp, udp, ssh traffic only from your public ip address).

Figure 1.0: Wazuh Manager service running.
![image](https://github.com/user-attachments/assets/022e4f4e-10ef-4b0f-9af8-1201f1a4e5b7)

### **Step 2: Configure Windows Host with Sysmon**
1. Install Sysmon on the Windows host to enhance telemetry collection:
   ```cmd
   sysmon -accepteula -i sysmonconfig.xml
   ```
2. Install the Wazuh agent and configure it to communicate with the server.
3. Confirm agent connectivity:
   ```cmd
   net start WazuhAgent
   ```

Figure 2.0: Sysmon and Wazuh Agent running on the Windows host.
![image](https://github.com/user-attachments/assets/f8c6db7a-784c-42e2-8dac-7024df2ea2dd)
![image](https://github.com/user-attachments/assets/1dfe7a89-fbb2-4f4c-be1d-8ce181e3fffd)



### **Step 3: Configure Wazuh for Log Collection**
1. Open the Wazuh web interface using the droplet’s IP address.
2. Register the Windows host in the “Agents” section.
3. Enable the archive module for log storage:
   - Edit `/var/ossec/etc/ossec.conf` to include `<archivist>`.
   - Restart Wazuh Manager:
     ```bash
     systemctl restart wazuh-manager
     ```

Figure 3.0: Logs from the Windows host displayed in Wazuh.
![image](https://github.com/user-attachments/assets/8e7226c1-1393-4d84-9f0d-82a11183e041)

### **Step 4: Detecting Mimikatz Installation**

1. **Purpose:**  
   Detect the presence of Mimikatz on the Windows host using logs from Sysmon and Wazuh.

2. **Detection Setup:**  
   - Ensure that Sysmon is configured to log critical events such as process creation.
   - Create or enable Wazuh rules to flag telemetry associated with Mimikatz.

3. **Steps for Detection:**  
   - Navigate to the Wazuh dashboard and filter logs for entries indicating the installation or execution of `mimikatz.exe`.  
   - Review Sysmon logs for relevant events, such as:
     - **Sysmon Event ID 1 (Process Creation):** Logs showing `mimikatz.exe` execution.
     - **Windows Event ID 4688:** Additional evidence of the process creation.  
   - Cross-reference flagged logs with system activity to validate the detection.

Figure 4.0: A log entry in the Wazuh dashboard showing the detection of `mimikatz.exe` installation.
![image](https://github.com/user-attachments/assets/aab1163e-8650-4124-a1a2-5d8a27ee3ab0)

## Creating Alerts to Detect Mimikatz Usage in Wazuh

### Overview
To detect Mimikatz activity, Wazuh's **Custom Rules** feature allows you to define specific conditions for generating alerts. This approach helps tailor detection capabilities to your environment.

---

### Step 1: Access Wazuh Custom Rules
1. Navigate to the **Rules** section in the Wazuh web interface.
2. Select **Custom Rules** to add a new detection rule.

---

### Step 2: Create a Detection Rule
1. Define a new custom rule to monitor for specific indicators of Mimikatz activity:
   - **Process Names:** Look for processes such as `mimikatz.exe`.
   - **Command-Line Arguments:** Detect arguments referencing Mimikatz usage.
   - **Targeted Actions:** Monitor interactions with sensitive processes like `lsass.exe`.

2. Example of of a custom rule added to Wazuh
![image](https://github.com/user-attachments/assets/8748cc92-d9df-4c21-a763-63d74c72c20c)

### Step 3: Verify Alerts
Simulate Mimikatz activity in a safe, controlled environment.
Open the Wazuh web interface and navigate to the Alerts section.
Confirm that alerts for Mimikatz execution detected or similar descriptions are generated.

![image](https://github.com/user-attachments/assets/fe3c2360-5450-4962-a988-9e4f5494cc22)






---

## **Conclusion**

This lab demonstrates how to deploy and configure Wazuh as a SIEM solution, collect telemetry using Sysmon, and analyze logs for security insights. The lab also emphasizes detecting advanced threats like Mimikatz to enhance cybersecurity defense strategies. These foundational steps are crucial for developing a robust security monitoring system.


---





