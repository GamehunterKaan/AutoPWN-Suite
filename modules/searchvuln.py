from modules.color import print_colored, colors, bcolors
from modules.nvdlib.nvdlib import searchCPE, getCVE
from textwrap import wrap
from os import get_terminal_size

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
        dontsearch = ['ssh', 'vnc', 'http', 'https', 'ftp', 'sftp', 'smtp', 'smb', 'smbv2']

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

def SearchSploits(HostArray,CPEArray):
    print_colored("\n---------------------------------------------------------", colors.red)
    print_colored("\tPossible vulnerabilities for " + str(HostArray[0][0]), colors.red)
    print_colored("---------------------------------------------------------", colors.red)
    keywords = GenerateKeywords(HostArray)
    if len(keywords) and len(CPEArray) == 0:
        print_colored("Insufficient information for " + str(HostArray[0][0]), colors.red)
    else:
        print("Searching vulnerability database for %s keywords and %s CPEs..." % (len(keywords),len(CPEArray)))
        for keyword in keywords:
            #https://github.com/vehemont/nvdlib
            #search the NIST vulnerabilities database for the generated keywords
            ApiResponse = searchCPE(keyword = str(keyword), cves=True)
            tempTitleList = []
            TitleList = []
            tempCVEList = []
            AllCVEs = []
            for CPE in ApiResponse:
                tempTitleList.append(CPE.title)
                for CVE in CPE.vulnerabilities:
                    tempCVEList.append(CVE)
            
            for cve in tempCVEList:
                if cve not in AllCVEs and not cve == '':
                    AllCVEs.append(cve)

            for title in tempTitleList:
                if title not in TitleList and not title == '':
                    TitleList.append(title)

            if len(TitleList) > 0:
                ProductTitle = min(TitleList)
                print_colored("\n┌─[ %s ]" % ProductTitle, colors.cyan)
                for CVE in AllCVEs:
                    print_colored("│\n├─────%s\n│" % (CVE), colors.bold)
                    CVEDetails = getCVE(CVE)
                    try:
                        description = str(CVEDetails.cve.description.description_data[0].value)
                    except:
                        description = "Could not fetch description for " + str(CVE)

                    try:
                        severity = CVEDetails.v3severity
                    except:
                        try:
                            severity = CVEDetails.v2severity
                        except:
                            severity = "Could not fetch severity for " + str(CVE)

                    try:
                        score = CVEDetails.v3score
                    except:
                        try:
                            score = CVEDetails.v2score
                        except:
                            score = "Could not fetch score for " + str(CVE)

                    try:
                        exploitability = CVEDetails.v3exploitability
                    except:
                        try:
                            exploitability = CVEDetails.v2exploitability
                        except:
                            exploitability = "Could not fetch exploitability for " + str(CVE)

                    try:
                        details = CVEDetails.url
                    except:
                        details = "Could not fetch details for " + str(CVE)

                    termsize = get_terminal_size()
                    wrapped_description = wrap(description, termsize.columns - 50)

                    print("│\t\tDescription : ")
                    for wrapped_part in wrapped_description:
                        print("│\t\t\t%s" % wrapped_part)
                    print("│\t\tSeverity : %s - %s" % (severity, score))
                    print("│\t\tExploitability : %s" % (exploitability))
                    print("│\t\tDetails : %s" % (details))

        for cpe in CPEArray:
            #search the NIST vulnerabilities database for CPEs
            ApiResponse = searchCPE(cpeMatchString=cpe, cves=True)
            for CPE in ApiResponse:
                if (not CPE.vulnerabilities[0] == '' and not set(CPE.vulnerabilities[0:3]).issubset(printedCVEs)):
                    #only print the first 3 CVEs
                    print(bcolors.cyan + "Product : " + bcolors.endc + CPE.title + bcolors.cyan + "\tCVEs : " + bcolors.endc + str(CPE.vulnerabilities[0:3]))
                    for CVE in CPE.vulnerabilities:
                        printedCVEs.append(CVE)
