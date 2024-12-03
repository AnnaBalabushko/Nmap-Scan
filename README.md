# Nmap-Scan

# Nmap Scanner in Python

This is a simple Python script that uses the `nmap` library to perform a port scan on a specified target host. The script scans the target host `scanme.nmap.org` (an example of a publicly accessible target for testing) and outputs the scan results, including the host state, protocols, and open ports.

## Features

- **Port Scanning**: The script scans the specified target for open ports using `nmap.PortScanner()`.
- **Protocol Detection**: It detects and prints protocols (e.g., TCP, UDP) for each open port.
- **Host Information**: The script prints out the state of each host and the state of each open port.

## Requirements

- **Python 3.x**: This script is written in Python 3.x.
- **nmap module**: The script uses the `nmap` module, which is a Python wrapper for the Nmap security scanner.
  
### Installation

To use this script, you need to install the `python-nmap` library and ensure that Nmap is installed on your system.

1. **Install Nmap**:

   If you don't have Nmap installed, you can install it as follows:

   - On **Linux** (Debian/Ubuntu):
     ```bash
     sudo apt-get install nmap
     ```

   - On **macOS**:
      ```bash
     brew install nmap
     ```

   - On **Windows**:
     Download and install Nmap from the official site: [https://nmap.org/download.html](https://nmap.org/download.html).

2. **Install the Python `nmap` Module**:

   Install the Python wrapper for Nmap using pip:

   ```bash
   pip install python-nmap
   ```

### Script Overview

The script uses the `nmap` library to scan a target host and gather information about open ports and services. Here's a breakdown of the code:

1. **Import the Nmap Module**:
   ```python
   import nmap
   ```

2. **Create a PortScanner Object**:
   ```python
   scanner = nmap.PortScanner()
   ```

3. **Specify the Target**:
   - The target in this case is set to `scanme.nmap.org`, a public test server provided by Nmap.
   ```python
   target = "scanme.nmap.org"
   ```

4. **Perform the Scan**:
   - The `scan()` method is called on the target, which starts the scan process. By default, this scans the most common 1000 ports.
   ```python
   scanner.scan(target)
   ```

5. **Print Results**:
   - The script then loops over all hosts detected and prints the state of the host, protocols, and port states.
   ```python
   for host in scanner.all_hosts():
       print("Host: ", host)
       print("State: ", scanner[host].state())
       for proto in scanner[host].all_protocols():
           print("Protocol: ", proto)
           ports = scanner[host][proto].keys()
           for port in ports:
               print("Port: ", port, "State: ", scanner[host][proto][port]['state'])
   ```

### Output

The script outputs information about the scanned host, including its state (up or down), the protocols (e.g., TCP, UDP), and the open ports along with their states (open, closed, filtered). Here's an example of what the output might look like:

```
Host:  scanme.nmap.org
State:  up
Protocol:  tcp
Port:  22 State:  open
Port:  80 State:  open
Protocol:  udp
Port:  161 State:  open
```

### Customization

- **Target**: You can modify the `target` variable to scan different IP addresses or domain names.
  ```python
  target = "example.com"  # Replace with your target
  ```
- **Port Range**: To scan specific ports, you can pass a range of ports to the `scan()` method:
  ```python
  scanner.scan(target, '22-80')  # Scan ports 22 to 80
  ```
- **Specific Protocols**: If you want to scan a specific protocol, you can specify it:
  ```python
  scanner.scan(target, arguments="-p 22 --tcp")  # Only scan TCP port 22
  ```

### Usage

1. **Run the Script**:
   You can run the script from the terminal or command prompt:
   ```bash
   python nmap_scan.py
   ```

2. **Modify Target**:
   If you want to scan a different target, simply replace the `target` variable with the IP address or domain name of your choice:
   ```python
   target = "192.168.1.1"  # Replace with your target
   ```

3. **Viewing Results**:
   After running the script, the results will be printed in the terminal, showing the host state, protocol, and open ports.

### Notes

- **Permissions**: Depending on your operating system and the ports being scanned, you might need to run the script with elevated privileges (e.g., as an administrator or with `sudo` on Linux).
- **Legal and Ethical Considerations**: Always ensure you have explicit permission before scanning networks or systems that you do not own. Unauthorized port scanning can be illegal and unethical.



