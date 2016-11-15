import sys


def makeFile(path_read,path_write):
    parse_file = open(path_write,"w+")
    string_aux=""
    try:
        with open(path_read,"r") as f:
            for line in f:
                if line in ['\n',' ']:
                    string_aux=""
                else:
                    string_aux+=line
                    if "Data" in line:
                        string_aux+="\n"
                        if "UDP" in string_aux or "TCP" in string_aux:
                            parse_file.write(string_aux)
    except:
        print "Unexpected error:", sys.exc_info()[0]
            
makeFile("cap.bs","bit.bs")
