# AutoPWN-Suite

AutoPWN Suite is a project for scanning vulnerabilities and exploiting systems automatically.

![Screenshot](images/autopwn.png)

# Installation

You will need [nmap](https://nmap.org) in order to use this tool.

On Debian based distros (Kali/Parrot etc.):

```
sudo apt install nmap
```

On Arch based distros (BlackArch/ArchAttack etc.):

```
sudo pacman -S nmap
```

After installing nmap you can just clone the repo

```
git clone https://github.com/GamehunterKaan/AutoPWN-Suite.git
```


# Usage

```
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

# Legal

You may not rent or lease, distribute, modify, sell or transfer the software to a third party. AutoPWN Suite is free for distribution, and modification with the condition that credit is provided to the creator and not used for commercial use. You may not use software for illegal or nefarious purposes. No liability for consequential damages to the maximum extent permitted by all applicable laws.
