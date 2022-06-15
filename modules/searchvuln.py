from modules.nvdlib.nvdlib import searchCPE, searchCVE, getCVE
from modules.logger import info, error, warning, success, println, banner, print_colored, colors, bcolors
from textwrap import wrap
from os import get_terminal_size
from dataclasses import dataclass

@dataclass
class Vuln:
    Software : str
    CVEs : list

#generate keywords to search for from the information gathered from the target
def GenerateKeywords(HostArray):
    keywords = []
    for port in HostArray:
        target = str(port[0])
        targetport = str(port[1])
        service = str(port[2])
        product = str(port[3])
        version = str(port[4])
        templist = []
        #dont search if keyword is equal to any of these
        dontsearch = ['ssh', 'vnc', 'http', 'https', 'ftp', 'sftp', 'smtp', 'smb', 'smbv2', 'linux telnetd']

        #if any of these equal to 'Unknown' set them to empty string
        if service == 'Unknown':
            service = ''
        
        if product == 'Unknown':
            product = ''
        
        if version == 'Unknown':
            version = ''

        if product.lower() not in dontsearch and not product == '':
            query1 = (product + ' ' + version).rstrip()
            templist.append(query1)

        for entry in templist:
            if entry not in keywords and not entry == '':
                keywords.append(entry)

    return keywords

def SearchKeyword(keyword, apiKey=None):
    #search for the keyword in the NVD database
    print(" " * 100, end="\r")
    print("Searching vulnerability database for keyword %s... CTRL-C to skip" % (keyword), end="\r")

    try:
        if apiKey == None:
            ApiResponseCPE = searchCPE(keyword=keyword)
            ApiResponseCVE = searchCVE(keyword=keyword)
        else:
            ApiResponseCPE = searchCPE(keyword=keyword, key=apiKey)
            ApiResponseCVE = searchCVE(keyword=keyword, key=apiKey)
    except KeyboardInterrupt:
        print(" " * 100, end="\r")
        error("Skipping vulnerability detection for keyword " + keyword)
        return '', []
    except LookupError:
        print(" " * 100, end="\r")
        error("NIST API returned an invalid response for keyword " + keyword)
        return '', []
    except Exception as e:
        print(" " * 100, end="\r")
        error("Error: " + str(e))
        return '', []

    tempTitleList = []
    TitleList = []
    for CPE in ApiResponseCPE:
        tempTitleList.append(CPE.title)

    for title in tempTitleList:
        if title not in TitleList and not title == '':
            TitleList.append(title)

    if len(TitleList) != 0:
        CPETitle = min(TitleList)
    else:
        CPETitle = ''
    
    print(" " * 100, end="\r")

    return CPETitle, ApiResponseCVE

def SearchSploits(HostArray, apiKey=None):
    VulnsArray = []
    target = str(HostArray[0][0])

    banner("Possible vulnerabilities for " + target, colors.red)

    keywords = GenerateKeywords(HostArray)

    if len(keywords) == 0:
        error("Insufficient information for " + target)
        return []

    info("Searching vulnerability database for %s keyword(s)...\n" % (len(keywords)))

    for keyword in keywords:
        #https://github.com/vehemont/nvdlib
        #search the NIST vulnerabilities database for the generated keywords
        CPETitle, ApiResponseCVE = SearchKeyword(keyword, apiKey)

        #if the keyword is found in the NVD database, print the title of the vulnerable software
        if CPETitle != '':
            Title = CPETitle
        elif CPETitle == '' and len(ApiResponseCVE) != 0:
            Title = keyword
        elif CPETitle == '' and len(ApiResponseCVE) == 0:
            continue

        # create a Vuln object
        VulnObject = Vuln(Software=Title, CVEs=[])

        println("\n\n┌─" + bcolors.yellow + "[ " + Title + " ]" + bcolors.endc)

        for CVE in ApiResponseCVE:
            println("│\n├─────┤ " + bcolors.red + str(CVE.id) + bcolors.endc + "\n│")

            description = str(CVE.cve.description.description_data[0].value)
            severity = str(CVE.score[2])
            score = str(CVE.score[1])
            details = CVE.url

            try:
                exploitability = str(CVE.v3exploitability)
            except AttributeError:
                try:
                    exploitability = str(CVE.v2exploitability)
                except AttributeError:
                    exploitability = "Could not fetch exploitability score for " + str(CVE.id)

            termsize = get_terminal_size()
            wrapped_description = wrap(description, termsize.columns - 50)

            println("│\t\t" + bcolors.cyan + "Description : " + bcolors.endc)
            for line in wrapped_description:
                println("│\t\t\t" + line)
            println("│\t\t" + bcolors.cyan + "Severity : " + bcolors.endc + severity + " - " + score)
            println("│\t\t" + bcolors.cyan + "Exploitability : " + bcolors.endc + exploitability)
            println("│\t\t" + bcolors.cyan + "Details : " + bcolors.endc + details)

            VulnObject.CVEs.append(str(CVE.id))

        VulnsArray.append(VulnObject)
        print(" " * 100, end="\r") #clear the line
        println("└" + "─" * 59)

    return VulnsArray