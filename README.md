# Reco — Lightweight Recon & Web Vulnerability Toolkit

Reco is an easy to use penetration testing toolkit written in **Go**, with a **Fyne-based GUI**.  
It’s designed especially for beginners in ethical hacking, making reconnaissance, enumeration, and vulnerability scanning simple.


## Features

### Reconnaissance & Information Gathering
- **User Enumeration**: Discover usernames across platforms (Instagram, Twitter, GitHub, Reddit, Facebook, etc.).
- **DNS Enumeration**: Identify subdomains using large wordlists.
- **Virtual Host Discovery**: Detect hidden virtual hosts via HTTP `Host` header manipulation.
- **Directory Enumeration**: Find hidden directories/files via bruteforce wordlists.
- **WHOIS Lookup**: Fetch domain registration and owner details.
- **Network Scanning**: Run port/service scans via **Nmap** integration.

### Advanced Vulnerability Scanning
- **Web Vulnerability Scanner**: Detect SQLi, XSS, Directory Traversal, Command Injection, XXE, CSRF.
- **SSL/TLS Scanner**: Detect weak ciphers, protocols, and certificate issues.
- **Email Harvester**: Collect email addresses from web pages and technical files.
- **Technology Detection**: Fingerprint CMSs, JS frameworks, server stacks, and analytics tools.

## Getting Started

### Prerequisites
- [Go](https://go.dev/) (v1.20 or newer)
- [Nmap](https://nmap.org/) (for network scanning features)
- Optional: Large wordlists for DNS/Directory scans

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/reco.git
cd reco

# Build the project
go build -o reco main.go

# Run the application
./reco    # Linux/macOS
reco.exe  # Windows


