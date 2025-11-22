```
 _______  _______  ______    ___   _______  _______  _______  _______  _______  __   __  _______
|       ||       ||    _ |  |   | |       ||       ||       ||       ||       ||  | |  ||       |
|  _____||       ||   | ||  |   | |    _  ||_     _||  _____||       ||   _   ||  | |  ||_     _|
| |_____ |       ||   |_||_ |   | |   |_| |  |   |  | |_____ |       ||  | |  ||  |_|  |  |   |  
|_____  ||      _||    __  ||   | |    ___|  |   |  |_____  ||      _||  |_|  ||       |  |   |  
 _____| ||     |_ |   |  | ||   | |   |      |   |   _____| ||     |_ |       ||       |  |   |  
|_______||_______||___|  |_||___| |___|      |___|  |_______||_______||_______||_______|  |___|

```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> ⚠️⚠️⚠️ LEGAL DISCLAIMER: This tool is designed for authorized security testing, red team operations, and defensive blue team assessments only. By using this tool, you agree that you have obtained prior explicit and written consent from the owner of the target systems and that you will comply with all applicable laws and regulations. Use of this tool against any target without prior explicit and written consent is illegal. The author assumes no responsibility for any misuse, unlawful activity, or damage caused by this tool.

## 📋 Overview

In an Active Directory scenario, it is possible to configure the automatic execution of a specific script following a particular event, these scripts are called “AD Automation Script” which typically are: Logon Script, LogOff Script, StartUp Script and Shutdown Script; if they are configured incorrectly, an attacker, broadly speaking, is able to impersonate the user who executes such Automation Script and this allows the attacker to perform Privilege Escalation and / or Persistency.

A total of 5 misconfigurations have been identified and they have been sequentially classified with the term SMISC (Script MISCconfiguration), in order to identify these SMISC automatically i have developed a Python tool called “ScriptScout”.

A dedicated in‑depth article that explains ScriptScout’s internals & usage is available at [Introducing ScriptScout: Transforming Smooth AD Automation Scripts into Attack Vectors](https://marcozufferli.com/posts/introducing_scripscouttransforming_smooth_ad_automation_scripts_into_attack_vectors/).

## 🚀 Quick Install

```
sudo apt install smbclient # ScriptScout's internals needs "smbcacls" tool which is inclued within the "smbclient" / "samba" packages.
python3 -m venv venv
source venv/bin/activate
python3 -m pip install termcolor dnspython impacket
```

## 📖 Usage
```
# python3 scriptscout.py --help

 _______  _______  ______    ___   _______  _______  _______  _______  _______  __   __  _______
|       ||       ||    _ |  |   | |       ||       ||       ||       ||       ||  | |  ||       |
|  _____||       ||   | ||  |   | |    _  ||_     _||  _____||       ||   _   ||  | |  ||_     _|
| |_____ |       ||   |_||_ |   | |   |_| |  |   |  | |_____ |       ||  | |  ||  |_|  |  |   |  
|_____  ||      _||    __  ||   | |    ___|  |   |  |_____  ||      _||  |_|  ||       |  |   |  
 _____| ||     |_ |   |  | ||   | |   |      |   |   _____| ||     |_ |       ||       |  |   |  
|_______||_______||___|  |_||___| |___|      |___|  |_______||_______||_______||_______|  |___|


usage: scriptscout.py [-h] -u USERNAME -p PASSWORD -d DOMAIN -ip-dc IP_ADDRESS_DOMAIN_CONTROLLER [-t TECHNIQUE] [-opsec OPSEC] -la LEGAL_AUTHORIZATION_CHECK

options:
  -h, --help            show this help message and exit
  -u, --username USERNAME
                        Insert the username
  -p, --password PASSWORD
                        Insert the password of the username
  -d, --domain DOMAIN   Insert the FULL domain of the username (e.g. WORLD.local is valid, WORLD is NOT valid)
  -ip-dc, --ip_address_domain_controller IP_ADDRESS_DOMAIN_CONTROLLER
                        Insert the IP Address of the Domain Controller target
  -t, --technique TECHNIQUE
                        Select the techinique to test (ALL | SMISC1 | SMISC2_and_SMISC3 | SMISC4 | SMISC5), by default it's ALL
  -opsec, --opsec OPSEC
                        Select the desired OPSEC level (ZERO | MEDIUM | HIGH), higher means longer sleep; by default it's MEDIUM
  -la, --legal_authorization_check LEGAL_AUTHORIZATION_CHECK
                        Confirm you have prior explicit written authorization from the infrastructure owner to run this tool; unauthorized or improper use is illegal and entirely the
                        user's responsibility; the author disclaims all warranties and any liability for misuse or damages. ( Y | N ) (by default it's N)
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
## ⚖️ Legal & Ethical Use

This tool is provided for **educational and authorized security testing purposes only**.

### ✅ Authorized Use
- Penetration testing with proper authorization
- Red team exercises with signed Rules of Engagement
- Security research in controlled lab environments
- Corporate security assessments with management approval

### ❌ Prohibited Use
- Unauthorized access to systems or data
- Violation of computer fraud laws (CFAA, GDPR, etc.)
- Any illegal activity

**By using this tool, you agree to use it responsibly and ethically. The author assumes no liability for misuse.**


