#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""%prog [options] [args]

DESCRIPTION

    Parse snort signatures and update database
EXAMPLES

    TODO: Show some examples of how to use this script.

EXIT STATUS

    TODO: List exit codes

AUTHOR

    Ole Morten Grodas 


VERSION
    $Id$
"""

import optparse
import sys
import os
import re
import csv

import psycopg2

from collections import defaultdict
from os.path import join as pjoin


def parse_options():
    parser =optparse.OptionParser(usage=globals()['__doc__'])
    parser.add_option ('-D', '--sigdir', help='Parse Snort signatures in this directory')
    parser.add_option ('-F', '--sigfile', help='Parse signature file')
    return parser.parse_args()

    
def main():
    (options, args) = parse_options()
    if options.sigdir:
        signature_files=(pjoin(options.sigdir,file) for file in os.listdir(options.sigdir) if file.endswith(".rules"))
    elif options.sigfile:
        signature_files=[options.sigfile]
    else:
        signature_files=[sys.stdin]
        
    signatures = parse_signatures(signature_files)
    
    updatedb(signatures)
     

def updatedb(signatures):
    try:
       conn=psycopg2.connect("dbname='ssm' user='ssm'") 
    except:
       print "I am unable to connect to the database, exiting."
       sys.exit()
       
    try:
        cursor=conn.cursor()
        cursor.executemany("""\
            INSERT INTO sigs (enabled,file,line,sid,rev,msg,classtype,action,proto,saddr,sport,dir,daddr,dport,options,reference) 
            VALUES (%(enabled)s,%(file)s,%(lineno)s,%(sid)s,%(rev)s,%(msg)s,%(classtype)s,%(action)s,%(proto)s,%(saddr)s,%(sport)s,%(dir)s,%(daddr)s,%(dport)s,%(stripped_options)s,%(reference)s);"""
        ,signatures)
        conn.commit()
    except psycopg2.DatabaseError:
        conn.rollback()
        raise
        
        
class Comment(Exception):pass
class EmptyLine(Comment):pass
class ParsingError(Exception):pass
class MissingSid(ParsingError):pass
class MissingRev(ParsingError):pass   
             
def parse_signatures(files):
    """
    """
    for file in files:
        signature=""
        lineno=0
        for line in open(file):
            lineno+=1
            if line.endswith("\\"):
                signature+=line[:-1] + " "
            else:
                signature+=line
                try:
                    parsed_signature=Signature(signature,file,lineno)
                    yield parsed_signature
                except EmptyLine,e:
                    pass
                except Comment,e:
                    pass
                except ParsingError,e:
                    sys.stderr.write("ParsingError: %s " % str(e))
                    raise
                signature=""
        

class Signature(object):
    """A python represenation of a snort signature"""

    opt_regexp=re.compile("""(?P<key>\S*?)(?::\s?(?P<value>[^"]*?|"[^"\\\r\n]*(?:\\.[^"\\\r\n]*)*"))?\s?;""")
    iscomment_regexp=re.compile("""^\s*#""")

    def __init__(self,text,filename,lineno):
        self.file=os.path.basename(filename)
        self.lineno=lineno
        text=text.strip()
        if not text:
            raise EmptyLine()
            
        if self.iscomment_regexp.match(text):
            self.enabled=False
            self.rawsignature=text.split('#',1)[1]
        else:
            self.enabled=True
            self.rawsignature=text
            
        try:
            #Extract signature header
            try:
                self.action,self.proto,self.saddr,self.sport,self.dir,self.daddr,self.dport,options=self.rawsignature.split(' ',7)
                self.options=options.split('(',1)[1].rsplit(')',1)[0] # Remove () from options
            except (ValueError,IndexError),e:
                raise ParsingError(self.rawsignature)

            if self.dir not in ["->","<-","<>"]:
                raise ParsingError(self.rawsignature)
            
            
            #Extract signature options
            self.optionsdict=defaultdict(list)
            self.stripped_options=""
            parsed_options=self.opt_regexp.findall(self.options)
            for key,value in parsed_options:
                self.optionsdict[key].append(value)
                if key not in ["msg","reference","rev","sid","classtype"]:
                    if value:
                        self.stripped_options+= "%s:%s; " %(key,value)
                    else:            
                        self.stripped_options+="%s; " % (key)
            
            #Setting default for some options that is expected in every sig, but is still missing in some 
            if "msg" not in self.optionsdict: self.optionsdict["msg"]=["Missing"]
            if "classtype" not in self.optionsdict: self.optionsdict["classtype"]=["Missing"]
            if "reference" not in self.optionsdict: self.optionsdict["reference"]=[""]

            try:int(self.sid)
            except TypeError,e: raise MissingSid(signature)

            try: int(self.rev)
            except TypeError,e: raise MissingRev(signature)
        except ParsingError,e:
            if self.enabled:
                raise
            else:
                raise Comment(text)
     
    def __getattr__(self,name):
        if name not in self.optionsdict:
            raise AttributeError(name) 
        value=self.optionsdict[name]
        if len(value)==1:
            return value[0]
        else:
            return value
            
    def __getitem__(self,name):
        try:
            return self.__dict__[name]
        except:
            return self.__getattr__(name)
        

if __name__=="__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt,e:
        sys.stderr.write("User presdd Ctrl+C. Exiting..\n")
