from modules.color import print_colored, colors, bcolors
from modules.nvdlib.nvdlib import searchCPE

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

def SearchSploits(HostArray):
    print_colored("\n---------------------------------------------------------", colors.red)
    print_colored("\tPossible vulnerabilities for " + str(HostArray[0][0]), colors.red)
    print_colored("---------------------------------------------------------", colors.red)
    keywords = GenerateKeywords(HostArray)
    if len(keywords) == 0:
        print_colored("Insufficient information for " + str(HostArray[0][0]), colors.red)
    else:
        print("Searching vulnerability database for %s keywords..." % (len(keywords)))
    for keyword in keywords:
        #https://github.com/vehemont/nvdlib
        #search the NIST vulnerabilities database for the generated keywords
        ApiResponse = searchCPE(keyword = str(keyword), cves=True)
        printedCVEs = []
        for CPE in ApiResponse:
            if (not CPE.vulnerabilities[0] == '' and not set(CPE.vulnerabilities[0:3]).issubset(printedCVEs)):
                #only print the first 3 CVEs
                print(bcolors.cyan + "Product : " + bcolors.endc + CPE.title + bcolors.cyan + "\tCVEs : " + bcolors.endc + str(CPE.vulnerabilities[0:3]))
                for CVE in CPE.vulnerabilities:
                    printedCVEs.append(CVE)