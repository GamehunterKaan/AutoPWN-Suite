# AutoPWN-Suite
AutoPWN Suite is my brand new project for scanning vulnerabilities and exploiting systems automatically.

![Screenshot](images/autopwn.png)

# Usage

```bash
usage: autopwn.py [-h] [-o OUTPUT] [-t TARGET] [-st SCANTYPE] [-y]

AutoPWN Suite

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file name. (Default:autopwn.log)
  -t TARGET, --target TARGET
                        Target range to scan. (192.168.0.1 or 192.168.0.0/24)
  -st SCANTYPE, --scantype SCANTYPE
                        Scan type. (Ping or ARP)
  -y, --yesplease       Don't ask for anything. (Full automatic mode)
```