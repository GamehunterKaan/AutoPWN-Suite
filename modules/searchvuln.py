from csv import reader
from modules.color import print_colored, colors
from modules.nvdlib.nvdlib import searchCPE

def GenerateKeywords(HostArray):
    keywords = []
    for port in HostArray:
        target = str(port[0])
        targetport = str(port[1])
        service = str(port[2])
        product = str(port[3])
        version = str(port[4])
        templist = []
        dontsearch = ['ssh', 'vnc', 'http', 'https', 'ftp', 'sftp', 'smtp', 'smb', 'smbv2']

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
    print_colored("---------------------------------------------------------", colors.red)
    print_colored("\tPossible vulnerabilities for " + str(HostArray[0][0]), colors.red)
    print_colored("---------------------------------------------------------", colors.red)
    keywords = GenerateKeywords(HostArray)
    for keyword in keywords:
        #https://github.com/vehemont/nvdlib
        print("Searching vulnerabilities for : " + keyword)
        ApiResponse = searchCPE(keyword = keyword, cves=True)
        for CPE in ApiResponse:
            if not len(CPE.vulnerabilities) == 0:
                print("Title : %s\tCVEs : %s" % (CPE.title, CPE.vulnerabilities))