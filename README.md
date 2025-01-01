# SIEM-Home-Lab

# Objective
This SIEM Home Lab project focused on deploying and configuring Wazuh as a Security Information and Event Management (SIEM) solution. This involved setting up the Wazuh server on DigitalOcean with secure firewalls and using Sysmon to collect telemetry from a Windows host. The objective was to establish a functional SIEM environment for log analysis and enhanced security monitoring.

# Skills Learned
- Deploying SIEM solutions on cloud platforms.
- Configuring telemetry collection from Windows hosts.
- Analyzing logs and events in a SIEM interface.
- Implementing secure network configurations.

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

### **Step 4: Log Analysis**
1. Use Wazuh’s dashboard to filter and review logs from the Windows host.
2. Focus on specific telemetry, such as process executions, file changes, and network connections.

**Screenshot:** Example log analysis from Wazuh dashboard.

---

## **Conclusion**
This lab demonstrates how to deploy and configure Wazuh as a SIEM solution, collect telemetry using Sysmon, and analyze logs for security insights. These foundational steps are crucial for developing a robust security monitoring system.

---

## **Next Steps**
- Enable real-time alerts in Wazuh.
- Integrate with Elastic Stack for advanced analytics.
- Expand to include additional endpoints and explore complex security scenarios.

**Attachments:** Screenshots referenced in the documentation.

