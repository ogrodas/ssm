#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Parse snort signatures and outputs the parsed signatures as json

EXAMPLES
    python rulesparser.py --outfile rules.json --debug --logfile rules.log ../etpro_rules/rules/ ../nhc_ids_rules/rules/
"""

USAGE ="parser.py [--outfile <file>] [--logfile <file>] [[rule dir] [rule file]]+"

import csv
import re
import sys
import argparse
import os
import logging
import json

from collections import defaultdict,OrderedDict
from os.path import join as pjoin

class ParsingError(Exception):pass

def parse_options(argv):
    parser = argparse.ArgumentParser(description=__doc__, usage=USAGE)
    parser.add_argument ('sigfiles', default="",nargs="+",help="files or dirs for snort sigs")
    parser.add_argument ('-O', '--outfile',default="")
    parser.add_argument ('-L', '--logfile',default="")
    parser.add_argument('--debug', action ='store_true',help = 'Outputs additional information to log.')

    args=parser.parse_args(argv)

    loglevel=logging.INFO
    if args.debug:
        loglevel=logging.DEBUG
    if args.logfile!="":
        logging.basicConfig(filename=args.logfile,level=loglevel,format='%(asctime)s %(levelname)s %(message)s')
    else:
        logging.basicConfig(level=loglevel,format='%(levelname)s %(message)s')
    return args
    
def main(argv):
    args =  parse_options(argv)
    files=[]
    for name in args.sigfiles:
        if os.path.isdir(name):
                for filename in os.listdir(name):
                    if filename.endswith(".rules"):
                        files.append(os.path.join(name,filename))
        elif os.path.isfile(name):
            files.append(name)

    
    sigs = parse_signatures(files)
    if not args.outfile:
        outfile=sys.stdout
    else:
        outfile=open(args.outfile,"w+")
    json.dump(sigs,outfile,indent=4)
    
    
def parse_signatures(files):
    sigs=[]
    for rulefile in files:
        logging.debug("%s: Start parsing" % (rulefile)) 
        comment=""
        with open(rulefile) as fp:
            linenum=0
            errornum=0
            signum=0
            for line in fp:
                linenum+=1
                if re.match("^\s*#?\s*?alert",line):
                    try:
                        sig=parse_signature(line.strip(),comment.strip(),rulefile,linenum)
                        signum+=1
                        sigs.append(sig)
                    except ParsingError,e:
                        errornum+=1
                        logging.error("%s:%d %s" % (rulefile,linenum,str(e)))
                    except Exception,e:
                        errornum+=1
                        logging.exception("%s:%d Error while parsing" % (rulefile,linenum))
                elif re.match("^\s*#",line): #Append comments
                    stripped=line.split("#",2)[1]
                    if stripped.strip():
                        comment+=stripped
                elif not line.strip(): #Remove comment if empty line
                    comment=""
                else:
                    logging.warning(line)
            
            logging.debug("%s: Finished Parsing %d Signatures, %d Errors, %d lines" % (rulefile,signum,errornum,linenum))
    return sigs

def parse_signature(rule,comment,filename,linenum):
    sig=OrderedDict()
    sig["comment"]=comment
    sig["filename"]=os.path.basename(filename)
    sig["linenum"]=linenum
    sig["sigtype"]="snort"

    iscomment_regexp=re.compile("""^\s*#""")
    if iscomment_regexp.match(rule):
        sig["enabled"]=False
        sig["sig"]=rule.split('#',1)[1].strip()
    else:
        sig["enabled"]=True
        sig["sig"]=rule
    
    try:
        sig["action"],sig["proto"],sig["src_ip"],sig["src_port"],sig["dir"],sig["dest_ip"],sig["dest_port"],options=sig["sig"].split(' ',7)
        options=options.split('(',1)[1].rsplit(')',1)[0] # Remove () from options
    except (ValueError,IndexError),e:
        raise ParsingError("Error rule parsing header")
     
    if sig["dir"] not in ["->","<-","<>","any"]:
        raise ParsingError('Rule dir is "%s" should be  "->","<-" or "<>"' % (sig["dir"]))

    #Extract signature options
    optionsdict=OrderedDict()
    stripped_options=""
    opt_regexp=re.compile("""(?P<key>\S*?)(?::\s?(?P<value>[^"]*?|"[^"\\\r\n]*(?:\\.[^"\\\r\n]*)*"))?\s?;""")
    parsed_options=opt_regexp.findall(options)
    for key,value in parsed_options:
        #if multiple keys, create a list of values
        if key not in optionsdict:
            optionsdict[key]=value
        elif not isinstance(optionsdict[key],list):
            optionsdict[key]=[optionsdict[key],value]
        else:
            optionsdict[key].append(value)

        #Create a stripped_options field that only includes functional options. Easier to read an understand what the sig does. 
        if key not in ["msg","reference","rev","sid","classtype","metadata"]:
            if value:
                stripped_options+= "%s:%s; " %(key,value)
            else:
                stripped_options+="%s; " % (key)
    sig["stripped_options"]=stripped_options


    #Add all non functional fields to the sig dictionary
    for key in ["reference","rev","sid","classtype"]:
        if key in optionsdict:
            opt=optionsdict[key]
            if isinstance(opt,list):
                sig[key]=[re.findall("^[\"']?(.*?)[\"']?$",el)[0] for el in opt] 
            else:
                sig[key]=re.findall("^[\"']?(.*?)[\"']?$",opt)[0] # Remove starting and ending "


    #Parse metadata
    if "metadata" in optionsdict:
        for key_value in optionsdict["metadata"].split(","):
            if ' ' in key_value:
                key,value=key_value.split(' ',1)
                sig["m."+ key]=value
            else:
                sig["m." +key_value]=""

    #Signature Validation
    if "msg" not in optionsdict: 
        logging.warning("%s:%d Signature missing msg" % (filename,linenum))
    if "classtype" not in optionsdict: 
        logging.info("%s:%d Signature missing classtype" % (filename,linenum))
    if "reference" not in optionsdict: 
        logging.info("%s:%d  missing reference" % (filename,linenum))
    if "sid" not in optionsdict:
        logging.warning("%s:%d Signature missing sid" % (filename,linenum))
    else:
        try:int(optionsdict["sid"])
        except TypeError,e: 
            logging.warning("%s:%d sid not and int" % (filename,linenum))
    if "rev" not in optionsdict:
        logging.warning("%s:%d Signature missing rev" % (filename,linenum))
    else:
        try:int(optionsdict["rev"])
        except TypeError,e: 
            logging.warning("%s:%d rev not and int" % (filename,linenum))
    return sig

if __name__=="__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt,e:
        sys.stderr.write("User presdd Ctrl+C. Exiting..\n")
