#-*- coding: UTF-8 -*-
import sys
import optparse
import urllib2
import socket
import time
import traceback
import json

from StringIO import StringIO

__VERSION__ = "0.0.1"

ENCODING = sys.getfilesystemencoding()

API = ""

#valid query api
MOBILE_DATA_TABLES = [
                      #these will contain url 、sample、event info
                      'url_domain',  # query detailed info by domain EXACTLY
                      'url_host',    # query detailed info by host EXACTLY
                      'url_url',     # query detailed info by url keywords
                      'sample_sha1', # query detailed info by sample sha1 EXACTLY
                      'event_mid',   # query detailed info by mid EXACTLY
                    
                      #this only contains host
                      'domain_host', # query hosts under the domain EXACTLY
                      'all_host_related', # query hosts all related with the host EXACTLY
                      'host_related', # query hosts related to the host EXACTLY
                      'hosts_low',   # query hosts whose domain's hosts between (low, low+20)
                      'hosts_high',  # query hosts whose domain's hosts between (high-20, high)

                      'firstdate',   # daily new domain_urls

                      'dns_info',     # data from netlab, query dns data about the domain
                      'same_ip',      # data from netlab, query hosts on the same ip
           
                      'whois',        # data from netlab, query whois about the domain
                      'email',        # data from netlab, domains under the same email, phone, name
                      'phone',
                      'name',
                      
                      'apkinfo',
                      ]

#
MOBILE_DATA_HDR = {
        #{u'sha1': u'17b0b8d3ba9c59db35a470af798add1c2e6e905a', u'pkgname': u'com.sec.android.providers.downloads', u'name''\u5b89\u5168', u'url': u'9979848539.haipengsh.com/2340000/300100_130786.apk', u'screen': u'on', u'mm': u'0e388d09b2372c', u'state': u'\u4e0b\u7ebf', u'time': u'18:21:17', u'date': u'2016-09-23'}
        'url_url' : '\t'.join(['sha1', 'pkgname', 'name', 'url', 'screen', 'mm', 'state', 'time', 'date']),
        'url_domain':'\t'.join(['sha1', 'pkgname', 'name', 'url', 'screen', 'mm', 'state', 'time', 'date']),
        'url_host' : '\t'.join(['sha1', 'pkgname', 'name', 'url', 'screen', 'mm', 'state', 'time', 'date']),
        'sample_sha1':'\t'.join(['sha1', 'pkgname', 'name', 'url', 'screen', 'mm', 'state', 'time', 'date']),
        'event_mm':'\t'.join(['sha1', 'pkgname', 'name', 'url', 'screen', 'mm', 'state', 'time', 'date']),
        
        'domain_host' : 'host',
        'hosts_low' : 'host',
        'hosts_high' : 'host',

        'firstdate' : 'url',

        'all_host_related' : 'host',
        'host_related' : '\t'.join(['path', 'host']),

        'dns_info' : '\t'.join(['time_first', 'time_last', 'hitscnt', 'key', 'type', 'value', 'source']),
        'same_ip'  : 'hosts',
        
        'whois' : '\t'.join(['domain', 'type', 'value']),
        'email' : 'domain',
        'phone' : 'domain',
        'name' : 'domain',

        'apkinfo' : '\t'.join(['name', 'pkgnam', 'level', 'status'])
        
        }

class MobileDataClient:
    TIMEOUT = 60
    MAX_RETRY = 1

    def __init__(self, api, api_id = None, api_key = None, verbose = False):
        self.api = api
        self.api_id = api_id
        self.api_key = api_key
        self.verbose = verbose

        #self defined dump function ptr
        self.MOBILE_DATA_DUMPFunctionPtr = {
            'dns_info'  : self.dnsinfo_dump,
            'whois'     : self.whois_dump,
            'firstdate' : self.firstdate_dump,
            }

    def __call__(self, f_table, f_keyword):
        self.f_table = f_table

        resp, data = self.query(f_table, f_keyword)

        #do whatever you need
        self.yourInterface(data)

        #
        self.dumpHDR(f_table)
        self.dump(f_table, data)
        
    def yourInterface(self, data):
        #you may only need to care about data['docs'], or data['detail']
        pass

    def logInfo(self, data):
        try:
            print(data.encode(ENCODING))
        except Exception, e:
            print(str(e))
            print(data)

    def dumpHDR(self, f_table):
        self.logInfo(MOBILE_DATA_HDR[f_table])

    def dump(self, f_table, data):
        try:
            #self defined dump functions
            self.MOBILE_DATA_DUMPFunctionPtr[f_table](data)
            
            #if exists, all finished
            return

        except Exception, e:
            pass
        
        #just move on
        docs = data['docs']
        for doc in docs:
            try:
                self.logInfo('\t'.join(item for item in doc.values()))
            except Exception, e:
                #self.logInfo(str(e))
                self.logInfo(doc)

    def _dump_list(self, ary):
        for item in ary:
            self.logInfo(item)

    def whois_dump(self, data):
        self._dump_list(data['detail'])

    def firstdate_dump(self, data):
        self._dump_list(data['url'])
        
        #this is domain
        self._dump_list(data['docs'].values())

    def dnsinfo_dump(self, data):
        '''
        dump info as you need

        $output = array('detail' => array(),          // from nt
                        'domain_hosts' => array(),    // some statistics
                        'ip' => array(),              // all ips within detail info
                        'same_ip' => array(),         // same_ip => array('ip1' => array(hosts), 'ip2' => array(hosts));
                        )
        '''
        self._dump_list(data['detail'])
        #self._dump_list(data['domain_hosts']) 
        #self._dump_list(data['ip'])
        #self._dump_list(data['same_ip'])

    def query(self, f_table, f_keyword):
        path = "/%s/%s"%(f_table, f_keyword)
        url = '%s%s' %(self.api, path)

        req = urllib2.Request(url)
        req = self.setup_header(req)

        return self._do_query(req, max_retry = self.MAX_RETRY)

    def _do_query(self, req, max_retry=0):
        def _safe_in_query(req):
            try:
                url = req.get_full_url()
                resp = urllib2.urlopen(req, timeout=self.TIMEOUT)
                data = resp.read()

                try:
                    data = json.loads(data)
                except Exception, e:
                    self.panic(data)

                if type(data) != type({}):
                    self.panic(">>> Server Exception: %s" %data, False)
                    return None
                
                return (resp, data)
            except socket.timeout:
                self.panic("[api timeout]: %s" %(url), False)
                return None
            except Exception, e:
                self.panic("[api error]:%s [%s]" %(url, str(e)))
                return None

        retry = max_retry + 1
        while (retry):
            ret = _safe_in_query(req)
            if ret is not None:
                return ret

            retry -= 1
            self.logInfo(">>> Retry...")
            time.sleep(1)
            continue
        
        return (None, None)
 
    def panic(self, error, hard=True):
        sys.stderr.write("%s\n" %error)
        if hard:
            sys.exit(1)

    def setup_header(self, req):
        req.add_header('Accept', 'application/json')
        if self.api_id:
            req.add_header('X-BashTokid', self.api_id)

        if self.api_key:
            pass
        
        return req

def usage():
    s = StringIO()
    s.write("Usage: %s <url_url>|<url_host>|<sample_sha1>|<event_mm> value\n"%sys.argv[0])
    
    l_infoAry = ["./mobile_data.py url_domain ryg5.com",
                 "./mobile_data.py url_host wy.ryg5.com",
                 "./mobile_data.py url_url sh2377    #(Slow, not recommend)",
                 "",

                 "./mobile_data.py sample_sha1 4f24a908d2e8efa5871cbdd93cd4e738857da156",
                 "./mobile_data.py event_mm 5eab324789c2e78b29b28a8ceb88dc8b",
                 "",
                 
                 "./mobile_data.py domain_host  ryg5.com",
                 "./mobile_data.py hosts_low  100    #(100 <= host_cnt < 120)  ",
                 "./mobile_data.py hosts_high 300    #(280 <= host_cnt < 300)",
                 "",

                 "./mobile_data.py firstdate 2016-12-15",
                 "",

                 "./mobile_data.py all_host_related ad.wd.daoudao.com",
                 "./mobile_data.py host_related  ad.wd.daoudao.com",
                 "",

                 "./mobile_data.py dns_info  daoudao.com",
                 "./mobile_data.py same_ip  211.144.132.60",
                 "./mobile_data.py whois baidu.com",
                 "./mobile_data.py email|phone|name xx@qq.com"
                 
                 "./mobile_data.py apkinfo md5"
                 ]

    for info in l_infoAry:
        s.write("\t%s\n"%info)
    s.write("\n")

    s.seek(0)
    return s.read()

def parse_option():
    parser = optparse.OptionParser(usage=usage())
    
    return parser

def main():
    
    global options, args
    parser = parse_option()
    options, args = parser.parse_args()
    
    if len(args) < 2:
        parser.print_help()
        sys.exit(1)

    f_table = args[0]
    if f_table not in MOBILE_DATA_TABLES:
        sys.stderr.write("Table must in %s\n" %("|".join(MOBILE_DATA_TABLES)))
        sys.exit(1)

    f_keyword = args[1]
   
    try:
        mobile_data = MobileDataClient(API)
        mobile_data(f_table, f_keyword)
    except KeyboardInterrupt, e:
        self.logInfo(">>> User Interrupt.")
    except Exception, e:
        sys.stderr.write("Client Exception")
        sys.stderr.write(traceback.format_exc())


if __name__ == "__main__":
    main()
