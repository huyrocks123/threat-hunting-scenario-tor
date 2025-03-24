<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/huyrocks123/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-03-23T02:39:39.9275793Z`. These events began at `2025-03-23T02:10:21.1481216Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "huy-vm"
| where InitiatingProcessAccountName == "huyrocks123"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-23T02:10:21.1481216Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, SHA256, Account = InitiatingProcessAccountName
```
<img width="1442" alt="Screenshot 2025-03-23 at 8 12 17 PM" src="https://github.com/user-attachments/assets/c229516b-ef3a-47a9-af90-617145b84bc2" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.7.exe". Based on the logs returned on March 22, 2025, at 10:26:12 PM, a file named "tor-browser-windows-x86_64-portable-14.0.7.exe" was run on a device called "huy-vm" by the user "huyrocks123." The file, located in the Downloads folder at "C:\Users\huyrocks123\Downloads", has a unique identifier (SHA256 hash) that ensures its authenticity. It was executed with a command to silently install it in the background without displaying any prompts or installation windows.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "huy-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1451" alt="Screenshot 2025-03-23 at 8 14 07 PM" src="https://github.com/user-attachments/assets/c784ce47-6fb2-4c97-acfa-eaaad9096f4e" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “huyrocks123” actually opened the tor browser. There was evidence they opened it at 2025-03-23T02:27:11.275709Z. There were several other instances of firefox.exe (Tor) and tor.exe that spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "huy-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
<img width="1464" alt="Screenshot 2025-03-23 at 8 17 02 PM" src="https://github.com/user-attachments/assets/a75a5fc9-fe14-4244-b149-ac9f36e5e59b" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. On March 22, 2025, at 10:28:55 PM, a successful connection was made from the device "huy-vm" by the user "huyrocks123." The connection was initiated by a program called "tor.exe," located in the folder "c:\users\huyrocks123\desktop\tor browser\browser\torbrowser\tor." The remote IP address of the connection was 46.231.93.216, and it was made through port 9001. There were a couple of other connections to sites over port 443. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "huy-vm"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe") 
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1440" alt="Screenshot 2025-03-23 at 8 18 36 PM" src="https://github.com/user-attachments/assets/ef9306e2-27e0-47ec-a107-c56aff732e46" />

---

## Chronological Event Timeline 

March 22, 202510:10:21 PM UTC - The file "tor-browser-windows-x86_64-portable-14.0.7.exe" was downloaded onto the device "huy-vm" by the user "huyrocks123."
  10:26:12 PM UTC - The installer "tor-browser-windows-x86_64-portable-14.0.7.exe" was executed from "C:\Users\huyrocks123\Downloads" in a silent mode.
  10:28:55 PM UTC - "tor.exe" successfully established a network connection over port 9001 to remote IP 46.231.93.216, indicating the activation of the Tor network.
  10:29:30 PM UTC - Additional network connections were detected from "tor.exe" over port 443.

March 23, 202502:27:11 AM UTC - The Tor browser was opened, leading to multiple processes spawning, including "firefox.exe" (Tor) and "tor.exe."
  02:39:39 AM UTC - A file named "tor-shopping-list.txt" was created on the desktop, potentially containing user activity or notes related to Tor usage.

---

## Summary

On March 22, 2025, at 10:10 PM UTC, the user "huyrocks123" on the device "huy-vm" downloaded a Tor browser installer. Shortly after, at 10:26 PM UTC, the installer "tor-browser-windows-x86_64-portable-14.0.7.exe" was executed in a silent installation mode from the Downloads folder. At 10:28 PM UTC, a successful network connection was established via "tor.exe" over port 9001 to a remote IP address (46.231.93.216), confirming the Tor browser's connection to the network. The user later opened the Tor browser at 02:27 AM UTC on March 23, 2025, leading to multiple instances of "firefox.exe" (Tor) and "tor.exe" spawning. The activity culminated in the creation of a file named "tor-shopping-list.txt" on the desktop at 02:39 AM UTC.

---

## Response Taken

TOR usage was confirmed on endpoint Huy-VM by user, huyrocks123. The device was isolated and the user's direct manager was notified.

---
