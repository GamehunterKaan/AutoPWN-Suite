from csv import reader
from modules.color import print_colored, colors

def GenerateKeywords(HostArray):
    keywords = []
    for port in HostArray:
        target = str(port[0])
        targetport = str(port[1])
        service = str(port[2])
        product = str(port[3])
        version = str(port[4])
        templist = []

        if service == 'Unknown':
            service = ''
        
        if product == 'Unknown':
            product = ''
        
        if version == 'Unknown':
            version = ''
        
        query1 = (product + ' ' + version).rstrip()
        query2 = (service + ' ' + version).rstrip()

        if not product == '':
            templist.append(query1)
        
        if not service == '':
            templist.append(query2)

        for entry in templist:
            if entry not in keywords and not entry == '':
                keywords.append(entry)

    return keywords

def SearchSploits(HostArray):
    print_colored("---------------------------------------------------------", colors.red)
    print_colored("\tPossible vulnerabilities for " + str(HostArray[0][0]), colors.red)
    print_colored("---------------------------------------------------------", colors.red)
    keywords = GenerateKeywords(HostArray)
    exploitsfile = open('modules/exploits.csv', 'rt')
    exploitreader = reader(exploitsfile, delimiter = ',')
    for row in exploitreader:
        for keyword in keywords:
            if keyword in row[2]:
                path = row[1]
                desc = row[2]
                exptype = row[5]
                platform = row[6]
                if exptype == 'remote' and platform == 'linux':
                    print("ExploitDB path : %s\t Description : %s\tType : %s\tPlatform : %s\n"
                        % (path, desc, exptype, platform))