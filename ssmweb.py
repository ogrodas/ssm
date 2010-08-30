#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import time
import subprocess
import psycopg2

import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.options
import tornado.autoreload
import tornado.escape

import simplejson as json

from tornado.options import define, options
define("port", default=8888, help="run on the given port", type=int)

ref_config= {
    "bugtraq":"http://www.securityfocus.com/bid/",
    "cve":"http://cve.mitre.org/cgi-bin/cvename.cgi?name=",
    "arachNIDS":"http://www.whitehats.com/info/IDS",
    "osvdb":"http://osvdb.org/show/osvdb/",
    "mcafee":"http://vil.nai.com/vil/content/v_",
    "nessus":"http://cgi.nessus.org/plugins/dump.php3?id=",
    "url":" http://",
    "arachnids":"http://www.whitehats.com/info/IDS",
}
   

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", Index),
            (r"/categories", Categories),
            (r"/signatures", Signatures),
            (r"/signature_details", SignatureDetails),
        ]
        settings = dict(
            login_url="/auth/login",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            debug=True,
            #xsrf_cookies=True,
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class Index(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html")
        
   
class Categories(tornado.web.RequestHandler):
    def get(self):
        results=db.query("SELECT classtype,count(*) from sigs group by classtype order by classtype")   
        formated_results=[(classtype,count) for (classtype,count) in results]
        formated_results.append(("all",str(sum(cat[1] for cat in formated_results))));
        self.write(json.dumps({"aaData":formated_results},sort_keys=True,indent=4))

      
class Signatures(tornado.web.RequestHandler):
    def get(self):
        #TODO: fix SQL injection
        where_filter=""
        if "classtype" in self.request.arguments:
            where_filter=" WHERE classtype='%s'" % (self.request.arguments["classtype"][0],)

        sql="SELECT enabled,msg,reference,sid,rev from sigs %s;" % (where_filter,)
        results=db.query(sql)
        
        formated_results=[]
        for (enabled,msg,references,sid,rev) in results:
            checked=""
            if enabled:
                checked=" checked"
            col1='''<img src="/static/images/details_open.png"><input type="checkbox" %s name="all" value="all">''' % (checked,)
            version="%s.%s" % (sid,rev)
            msg=msg[1:-1]
            if msg.startswith("ET "):
                msg=" ".join(msg.split(" ")[2:])
            reflist=[ref.split(",") for ref in re.findall("\"(.*?)\"",references)]
            refs=", ".join("<a href='%s' target='_blank'>%s</a>" % (ref_config[ref[0]] + ref[1],ref[0]) for ref in reflist)
            #row=map(tornado.escape.xhtml_escape,(col1,msg,ref,version))
            row=(col1,msg,refs,version)
            formated_results.append(row)
        self.write(json.dumps({"aaData":formated_results},sort_keys=True,indent=4))

        
class SignatureDetails(tornado.web.RequestHandler):
    def get(self):
        sid,rev = self.request.arguments["sidrev"][0].split(".")
        sql="SELECT action, proto,saddr,sport,dir,daddr,dport,options from sigs where sid=%s and rev=%s" % (sid,rev)
        results=db.query(sql)
        rule="%s %s %s %s %s %s %s (%s)" % results[0]
        self.write(rule)

        
class Database:
    def __init__(self,conn_str):
        self.connection=psycopg2.connect(conn_str)

    def query(self,query):
        cursor=self.connection.cursor()
        cursor.execute(query)
        return cursor.fetchall()
db=Database("host=127.0.0.1 dbname=ssm user=ssm")
        
        
def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.autoreload.start()
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
