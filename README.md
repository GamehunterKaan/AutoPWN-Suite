# AutoPWN Suite

AutoPWN Suite is a project for scanning vulnerabilities and exploiting systems automatically.
![Banner](https://raw.githubusercontent.com/GamehunterKaan/AutoPWN-Suite/main/images/banner.png)

## How does it work?

AutoPWN Suite uses nmap TCP-SYN scan to enumerate the host and detect the version of softwares running on it. After gathering enough information about the host, AutoPWN Suite automatically generates a list of "keywords" to search [NIST vulnerability database](https://www.nist.gov/).

### Sample output

AutoPWN Suite has a very user friendly easy to read output.

![Screenshot](https://raw.githubusercontent.com/GamehunterKaan/AutoPWN-Suite/main/images/autopwn.png)

### Installation

You will need [nmap](https://nmap.org) in order to use this tool.

On Debian based distros (Kali/Parrot etc):

```
sudo apt install nmap
```

On Arch based distros (BlackArch/ArchAttack etc):

```
sudo pacman -S nmap
```

After installing nmap you can just clone the repo.

```
git clone https://github.com/GamehunterKaan/AutoPWN-Suite.git
```
### Usage

```
usage: autopwn.py [-h] [-o OUTPUT] [-t TARGET] [-st SCANTYPE] [-s SPEED] [-a API] [-y] [-e]

AutoPWN Suite

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file name. (Default : autopwn.log)
  -t TARGET, --target TARGET
                        Target range to scan. (192.168.0.1 or 192.168.0.0/24)
  -st SCANTYPE, --scantype SCANTYPE
                        Scan type. (Ping or ARP)
  -s SPEED, --speed SPEED
                        Scan speed. (0-5)
  -a API, --api API     Specify API key for vulnerability detection for faster scanning. You can also specify your api key in api.txt file. (Default : None)
  -y, --yesplease       Don't ask for anything. (Full automatic mode)
  -e, --evade           Evade the detection of the scanner. (Warning : Slower and slightly inaccurate!)
```

### Contributing to AutoPWN Suite

I would be glad if you are willing to contribute this project. I am looking forward to merge your pull request unless its something that is not needed or just a personal preference. [Click here for more info!](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/CONTRIBUTING.md)


### Legal

You may not rent or lease, distribute, modify, sell or transfer the software to a third party. AutoPWN Suite is free for distribution, and modification with the condition that credit is provided to the creator and not used for commercial use. You may not use software for illegal or nefarious purposes. No liability for consequential damages to the maximum extent permitted by all applicable laws.


### Support or Contact

Having trouble using this tool? You can reach me out on [discord](https://github.com/GamehunterKaan/GamehunterKaan/blob/main/README.md) or create an issue!
