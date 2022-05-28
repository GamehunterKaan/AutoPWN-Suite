from datetime import datetime

def InitializeOutput(context):
    global outfile
    outfile = context

class output:
    def OutputBanner(target, scantype, speed, hostfile):
        filename = outfile
        file = open(filename, 'w')
        file.write("\n" + "-" * 50)
        file.write("\n" + "AutoPWN Suite")
        file.write("\n" + "Author: GamehunterKaan")
        file.write("\n" + "-" * 50)
        if hostfile:
            file.write("\n" + "Targets list: " + hostfile)
        else:
            file.write("\n" + "Target: " + target)
        file.write("\n" + "Scan type: " + scantype)
        file.write("\n" + "Scan speed: " + str(speed))
        file.write("\n" + "-" * 50)
        file.write("\n" + "Started at: " + str(datetime.now()))
        file.write("\n" + "-" * 50)
        file.close()
    def WriteToFile(data):
        filename = outfile
        file = open(filename, 'a')
        file.write("\n" + data)
        file.close()