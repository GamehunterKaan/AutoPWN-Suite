# AutoPWN Suite

AutoPWN Suite is a project for scanning vulnerabilities and exploiting systems automatically.

![Repo Size](https://img.shields.io/github/repo-size/GamehunterKaan/AutoPWN-Suite)
![GitHub top language](https://img.shields.io/github/languages/top/GamehunterKaan/AutoPWN-Suite)
[![Tests](https://github.com/GamehunterKaan/AutoPWN-Suite/actions/workflows/tests.yml/badge.svg)](https://github.com/GamehunterKaan/AutoPWN-Suite/actions/workflows/tests.yml)
[![CodeQL](https://github.com/GamehunterKaan/AutoPWN-Suite/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/GamehunterKaan/AutoPWN-Suite/actions/workflows/codeql-analysis.yml)
![GitHub issues](https://img.shields.io/github/issues-raw/GamehunterKaan/AutoPWN-Suite)
![GitHub closed issues](https://img.shields.io/github/issues-closed-raw/GamehunterKaan/AutoPWN-Suite)
![GitHub](https://img.shields.io/github/license/GamehunterKaan/AutoPWN-Suite)
![GitHub Repo stars](https://img.shields.io/github/stars/GamehunterKaan/AutoPWN-Suite?style=social)
![Banner](https://raw.githubusercontent.com/GamehunterKaan/AutoPWN-Suite/main/images/banner.png)

## Features
- Fully automatic! (Use `-y` flag to enable)
- Detect network IP range without any user input. 
- Vulnerability detection based on version.
- Get information about the vulnerability right from your terminal.
- Automatically download exploit related with vulnerability.
- Noise mode for creating a noise on the network.
- Evasion mode for being sneaky.
- Automatically decide which scan types to use based on privilege.
- Easy to read output.
- Function to output results to a file.
- Argument for passing custom nmap flags.
- Specify your arguments using a config file.

## How does it work?

AutoPWN Suite uses nmap TCP-SYN scan to enumerate the host and detect the version of softwares running on it. After gathering enough information about the host, AutoPWN Suite automatically generates a list of "keywords" to search [NIST vulnerability database](https://www.nist.gov/).

[Visit "PWN Spot!" for more information](https://pwnspot.com/posts/AutoPWN/)

## Demo

AutoPWN Suite has a very user friendly easy to read output.

[![asciicast](https://asciinema.org/a/497930.svg)](https://asciinema.org/a/497930)


## Installation

You can install it using pip. (sudo recommended)

```
sudo pip install autopwn-suite
```

OR

You can clone the repo.

```
git clone https://github.com/GamehunterKaan/AutoPWN-Suite.git
```
OR

You can download debian (deb) package from [releases.](https://github.com/GamehunterKaan/AutoPWN-Suite/releases)

```
sudo apt-get install ./autopwn-suite_1.2.7.deb
```

OR

You can use Google Cloud Shell.

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/GamehunterKaan/AutoPWN-Suite.git)

## Usage

Running with root privileges (sudo) is always recommended.

Automatic mode (This is the intended way of using AutoPWN Suite.)

```console
autopwn-suite -y
```

Help Menu

```console
$ autopwn-suite -h
usage: autopwn.py [-h] [-o OUTPUT] [-t TARGET] [-hf HOSTFILE] [-st {arp,ping}] [-nf NMAPFLAGS] [-s {0,1,2,3,4,5}] [-a API] [-y] [-m {evade,noise,normal}] [-nt TIMEOUT] [-c CONFIG] [-v]

AutoPWN Suite

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file name. (Default : autopwn.log)
  -t TARGET, --target TARGET
                        Target range to scan. This argument overwrites the hostfile argument. (192.168.0.1 or 192.168.0.0/24)
  -hf HOSTFILE, --hostfile HOSTFILE
                        File containing a list of hosts to scan.
  -st {arp,ping}, --scantype {arp,ping}
                        Scan type.
  -nf NMAPFLAGS, --nmapflags NMAPFLAGS
                        Custom nmap flags to use for portscan. (Has to be specified like : -nf="-O")
  -s {0,1,2,3,4,5}, --speed {0,1,2,3,4,5}
                        Scan speed. (Default : 3)
  -a API, --api API     Specify API key for vulnerability detection for faster scanning. (Default : None)
  -y, --yesplease       Don't ask for anything. (Full automatic mode)
  -m {evade,noise,normal}, --mode {evade,noise,normal}
                        Scan mode.
  -nt TIMEOUT, --noisetimeout TIMEOUT
                        Noise mode timeout. (Default : None)
  -c CONFIG, --config CONFIG
                        Specify a config file to use. (Default : None)
  -v, --version         Print version and exit.
```
## Currently working on
- Rewrite the nmap module from scratch
- https://github.com/GamehunterKaan/AutoPWN-Suite/issues/9

## TODO

Do you have a cool feature idea? [Create a feature request!](https://github.com/GamehunterKaan/AutoPWN-Suite/issues/new?assignees=&labels=&template=feature_request.md&title=)

- [x] 11 completed.
- [ ] https://github.com/GamehunterKaan/AutoPWN-Suite/issues/9
- [ ] Support for smaller terminals.
- [ ] Arch Linux package for Arch based systems like BlackArch and ArchAttack.
- [ ] Seperate script for checking local privilege escalation vulnerabilities.
- [ ] Windows and OSX support.
- [ ] Function to brute force common services like `ssh`, `vnc`, `ftp` etc.
- [ ] Built in reverse shell handler that automatically stabilizes shell like [pwncat](https://github.com/calebstewart/pwncat).
- [ ] Function to generate reverse shell commands based on IP and port.
- [ ] GUI interface.
- [ ] Meterpreter payload generator with common evasion techniques.
- [ ] Fileless malware unique to AutoPWN Suite.
- [ ] Daemon mode.
- [ ] Option to email the results automatically.
- [ ] Web application analysis.
- [ ] Web application content discovery mode. (dirbusting)
- [ ] Option to use as a module.

## Contributing to AutoPWN Suite

I would be glad if you are willing to contribute this project. I am looking forward to merge your pull request unless its something that is not needed or just a personal preference. [Click here for more info!](https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/.github/CONTRIBUTING.md)


## Legal

You may not rent or lease, distribute, modify, sell or transfer the software to a third party. AutoPWN Suite is free for distribution, and modification with the condition that credit is provided to the creator and not used for commercial use. You may not use software for illegal or nefarious purposes. No liability for consequential damages to the maximum extent permitted by all applicable laws.


## Support or Contact

Having trouble using this tool? You can reach me out on [discord](https://search.discordprofile.info/374953845438021635), [create an issue](https://github.com/GamehunterKaan/AutoPWN-Suite/issues/new/choose) or [create a discussion!](https://github.com/GamehunterKaan/AutoPWN-Suite/discussions)
