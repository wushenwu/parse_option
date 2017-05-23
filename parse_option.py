#!/usr/bin/env python
import sys
import os

import optparse
import codecs
from StringIO import StringIO

try:
    import json
except ImportError:
    import simplejson as json

import traceback

__VERSION__ = "1.0"

def ensureSysStdoutEncoding():
    encode = None
    if encode == None and sys.stdout.encoding != None:
        encode = sys.stdout.encoding
    if encode == None and sys.stdin.encoding != None:
        encode = sys.stdin.encoding
    if encode == None and sys.stderr.encoding != None:
        encode = sys.stderr.encoding
    if encode == None and sys.getdefaultencoding() != None:
        encode = sys.getdefaultencoding()
    if encode == None:
        encode = "UTF-8"
    if sys.stdout.encoding == None:
        sys.stdout = codecs.getwriter(encode)(sys.stdout)

ensureSysStdoutEncoding()

DEFAULT_CONFIG_FILE = ''
API = ""
TOKEN = ""
def parse_config(cfg_fname):
    config = {}
    cfg_files = filter(os.path.isfile,
            (cfg_fname, os.path.expanduser('~/.token')))

    if not cfg_files:
        raise Exception("No token file found")

    try:
        for fname in cfg_files:
            for line in open(fname):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    continue
                key, eq, val = line.partition('=')
                key = key.strip()
                val = val.strip().strip('"')
                config[key] = val
    except:
        raise Exception("Token file '%s' parse error", cfg_fname)
    return config

def usage():
    s = StringIO()
    s.write("Usage:  %s [options] [data]\n" %sys.argv[0])
    s.write("\t%s -i inputfile\n" %sys.argv[0])
    s.write("\t%s -o outdir\n" %sys.argv[0])
    s.seek(0)
    return s.read()
    
def parse_option():
    parser = optparse.OptionParser(usage=usage())
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
            help="For more details")
    parser.add_option("-V", "--version", dest="version", action="store_true",
            help="Show the version")  
    parser.add_option("-l", "--limit",   dest="limit",   action="store", type="int",    default=100, 
            help="Limit number of results.[default: %default]")
    
    return parser
    
class Client():
    def __init__(self, api, token, options):
        self.api = api
        self.token = token
        self.frequency = ""
        self.options = options
        if self.options.verbose:
            print api, token, options
    
    def do():
        pass
    
if __name__ == "__main__":
    parser = parse_option()
    options, args = parser.parse_args()
    options.TIMEOUT =  300
    
    if options.version:
        print "%s" % __VERSION__
        sys.exit(0)
    if len(args) != 0:
        parser.print_help()
        sys.exit(1)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    try:
        config = parse_config(options.config)
    except Exception, e:
        sys.stderr.write("%s\n" %e.message)
        sys.exit(1)

    API = API or config.get("API", "")
    TOKEN = config.get("TOKEN", "") or TOKEN

    try:
        client = Client(API, TOKEN, options)
        client.do()
    except KeyboardInterrupt, e:
        sys.stderr.write(">>> User Interrupt.")
    except Exception, e:
        sys.stderr.write("Client Exception")
        sys.stderr.write(traceback.format_exc())