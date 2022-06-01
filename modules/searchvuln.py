from modules.color import print_colored, colors, bcolors
from modules.nvdlib.nvdlib import searchCPE, searchCVE, getCVE
from textwrap import wrap
from os import get_terminal_size
from requests.exceptions import JSONDecodeError
from modules.outfile import WriteToFile

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

def SearchSploits(HostArray, apiKey):
    print_colored("\n" + "-" * 60, colors.red)
    print_colored(("Possible vulnerabilities for " + str(HostArray[0][0])).center(60), colors.red)
    print_colored("-" * 60 + "\n", colors.red)
    WriteToFile("\nPossible vulnerabilities for " + str(HostArray[0][0]))
    keywords = GenerateKeywords(HostArray)
    if len(keywords) <= 0:
        print_colored(("Insufficient information for " + str(HostArray[0][0])).center(60), colors.yellow)
        WriteToFile("Insufficient information for " + str(HostArray[0][0]))
    else:
        print("Searching vulnerability database for %s keyword(s)...\n" % (len(keywords)))
        WriteToFile("Searching vulnerability database for %s keyword(s)..." % (len(keywords)))
        for keyword in keywords:
            #https://github.com/vehemont/nvdlib
            #search the NIST vulnerabilities database for the generated keywords
            print(" " * 100, end="\r")
            print("Searching vulnerability database for keyword %s... CTRL-C to skip" % (keyword), end="\r")
            try:
                if apiKey:
                    ApiResponseCPE = searchCPE(keyword = str(keyword), key = str(apiKey))
                else:
                    ApiResponseCPE = searchCPE(keyword = str(keyword))
                tempTitleList = []
                TitleList = []
                for CPE in ApiResponseCPE:
                    tempTitleList.append(CPE.title)

                for title in tempTitleList:
                    if title not in TitleList and not title == '':
                        TitleList.append(title)
                
                print(" " * 100, end="\r")

                if len(TitleList) > 0:
                    ProductTitle = min(TitleList)
                    print_colored("\n\n┌─[ %s ]" % ProductTitle, colors.yellow)
                    WriteToFile("\n\n┌─[ %s ]" % ProductTitle)

                    if apiKey:
                        ApiResponseCVE = searchCVE(keyword = str(keyword), key = str(apiKey))
                    else:
                        ApiResponseCVE = searchCVE(keyword = str(keyword))
                    
                    for CVE in ApiResponseCVE:
                        print("│\n├─────┤ " + bcolors.red + str(CVE.id) + bcolors.endc + "\n│")
                        WriteToFile("│\n├─────┤ " + str(CVE.id) + "\n│")

                        try:
                            description = str(CVE.cve.description.description_data[0].value)
                        except:
                            description = "Could not fetch description for " + str(CVE.id)

                        try:
                            severity = str(CVE.v3severity)
                        except:
                            try:
                                severity = str(CVE.v2severity)
                            except:
                                severity = "Could not fetch severity for " + str(CVE.id)

                        try:
                            score = str(CVE.v3score)
                        except:
                            try:
                                score = str(CVE.v2score)
                            except:
                                score = "Could not fetch score for " + str(CVE.id)

                        try:
                            exploitability = str(CVE.v3exploitability)
                        except:
                            try:
                                exploitability = str(CVE.v2exploitability)
                            except:
                                exploitability = "Could not fetch exploitability for " + str(CVE.id)

                        try:
                            details = CVE.url
                        except:
                            details = "Could not fetch details for " + str(CVE.id)

                        termsize = get_terminal_size()
                        wrapped_description = wrap(description, termsize.columns - 50)

                        print("│\t\t" + bcolors.cyan + "Description : " + bcolors.endc)
                        WriteToFile("│\t\t" + "Description : ")
                        for line in wrapped_description:
                            print("│\t\t\t" + line)
                            WriteToFile("│\t\t\t" + line)
                        print("│\t\t" + bcolors.cyan + "Severity : " + bcolors.endc + severity + " - " + score)
                        WriteToFile("│\t\t" + "Severity : " + severity + " - " + score)
                        
                        print("│\t\t" + bcolors.cyan + "Exploitability : " + bcolors.endc + exploitability)
                        WriteToFile("│\t\t" + "Exploitability : " + exploitability)
                        
                        print("│\t\t" + bcolors.cyan + "Details : " + bcolors.endc + details)
                        WriteToFile("│\t\t" + "Details : " + details)

            except JSONDecodeError:
                print_colored("An error occurred while trying to fetch details for " + str(keyword), colors.red)
                WriteToFile("An error occurred while trying to fetch details for " + str(keyword))
            except KeyboardInterrupt:
                print_colored("Skipping vulnerability detection for keyword " + str(keyword), colors.red)
                WriteToFile("Skipped vulnerability detection for keyword " + str(keyword))
