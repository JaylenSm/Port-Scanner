# Port-Scanner

This is a functional port scanner which can query some protocols accurately, while sending generic "HEAD" HTTP packets to ports outside of the payloads. The scanner allows the user to have a friendly way of verifying the legitimacy (host verification) and responsiveness of a host (ping scans), as well as scanning a range of ports for both TCP and UDP. Banner grabbing is apart of this scanner, however, the ports for accurate querying are limited as mentioned before. But, some ports can be expected to auto-respond with the service, although it should not be relied on for accurate interpretation. The banner grabs will be performed on the specified port range.


## 📄 License

MIT License — see [LICENSE](LICENSE) for details.


## 📜 Table of Contents

- [Features](#Features)
- [Usage](#Usage)
- [Presentation](#Presentation)
- [Requirements](#Requirements)
- [Installation](#Installation)


# Features

- This port scanner features verification of legitimacy of hosts through resolving the DNS of a host. An IP can also be provided if it is known. Ping scans can be performed to see if a host is responding to ping attempts.

- TCP scanning is accurately handled by this port scanner, without many complex overheads performed compared to other more furbished port scanners. However, it can be a good tool for accurately verifying results of other scanners regarding TCP scans.

- UDP scanning doesn't have as much verbose handling as other well-established scanners. However, UDP scanning can be accurately done if no overly unexpected interactions occur. Which would be typically caused by a firewall being utilized on the host.

- Scanning can be performed for both ports at the same time. And it is necessary to scan both ports at the same time to perform banner grabbing. This was done to simplify banner grabbing.

# Usage

The usage of this tool is to be a supplement to other cli tools in a more friendly way to users who can't work complex command-based tools. As this tool provides a UI which provides an abstract way for verification of services and hosts without needing to be tech-minded. 

# Presentation

For a presentation/demo of the project [CLICK ME](https://1drv.ms/p/c/8d3e98d829540707/ESvu3V1S6vJGjr9dlvnkVU0BGHtKPD3NyqD_e2FWwZP65Q?e=okM3HH).

# Requirements 

- Make sure you are using a system compatible with the tool. The tool is pretty much compatible with most modern systems where socket access is available to the user (Linux, Windows, MacOS).

- Make sure when it comes to Windows, due to the utilage of Scapy, Npcap will need to be installed as Winpcap can be said to be outdated. In MacOS, root level privileges will be needed for the program to function properly. If any security hardening is present in your system, root privileges will also be needed in your system.

- Make sure that the latest version of Python3 is installed and utilized for the best performance. And that the scapy library is properly installed in your dedicated REPL (pip install scapy). Other libraries utilized are standard libraries and will not have to be manually installed.

# Installation

For this tool to function properly both files will need to be installed from the dedicated folder for the source code ("src/"). They will need to be installed in the same directory, in a way a Pythonic interpreter can reach them. Python3 will need to be installed along with scapy for the tool to even open. Make sure the tool is being ran with admin privileges or in a way where direct admin privileges are not necessary. 


### 🔖 Tags

`#python` `#cybersecurity` `#networking` `#port-scanner` `OSINT` `#cli-tools` `#ethical-hacking`
