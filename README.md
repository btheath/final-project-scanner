# final-project-scanner

Bash script to scan for network vulnerabilities and generate reports. 

## Overview
This project is a Bash-based tool that scans a target IP address or hostname for open ports and running services, then generates a formatted security report summarizing the findings. It is designed to grow from a simple report template into a scanning and reporting tool that identifies potential vulnerabilities and offers remediation recommendations.

## Purpose
This project was built for a shell scripting class, with a focus on network and device security, shell scripting fundamentals, and best programming practices such as modular function design, command-line argument handling, input validation, and use of external tools like `nmap`.

## Current Status
Initial setup and basic port scanning functionality implemented. The script accepts a target as a command-line argument, validates input, and uses a live `nmap` scan piped through `grep` to dynamically populate the "Open Ports" section of the report.

## Future Goals
Will be expanded to include vulnerability identification and detailed reporting, including parsing scan results against known CVEs and generating more robust, professional-grade remediation recommendations.
