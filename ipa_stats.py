#!/usr/bin/python
# -*- coding: utf-8 -*-

import ldap
import re
import collectd

instances = []

#Base
dn="cn=ldbm database,cn=plugins,cn=config"
pagesize=8192

#DNs we are interested in for IPA monitoring 
userRoot={}
ipaca={}
changelog={}
monitor={}
ldbm={}
 
class DBStats(object):
    def __init__(self,hostname=None,port=389,binddn=None,bindpw=None):
        self.hostname = hostname
        self.binddn = binddn
        self.bindpw = bindpw
        self.port = int(port)
        if self.hostname != None:
            self.__parse_entries__()
            
    def __parse_entries__(self):
        self.srv = ldap.open(self.hostname, self.port)
        if self.binddn != None:
            self.srv.simple_bind_s(self.binddn, self.bindpw)
        result = self.srv.search_s(dn,ldap.SCOPE_SUBTREE)
        for name,attrs in result:
            # iterate over DNs we are interested in and load values into dicts
            if name == "cn=database,cn=monitor,cn=ldbm database,cn=plugins,cn=config":
                monitor['nsslapd-db-cache-size-bytes'] = attrs['nsslapd-db-cache-size-bytes'][0]
                monitor['nsslapd-db-page-ro-evict-rate'] = attrs['nsslapd-db-page-ro-evict-rate'][0]
                monitor['nsslapd-db-page-rw-evict-rate'] = attrs['nsslapd-db-page-rw-evict-rate'][0]
                monitor['nsslapd-db-pages-in-use'] = attrs['nsslapd-db-pages-in-use'][0]
            elif name == "cn=monitor,cn=ldbm database,cn=plugins,cn=config":
                ldbm['dbcachehitratio']= attrs['dbcachehitratio'][0]
                ldbm['dbcachepagein']= attrs['dbcachepagein'][0]
                ldbm['dbcachepageout']= attrs['dbcachepageout'][0]
            elif re.search("cn=monitor, *cn=[a-zA-Z0-9][a-zA-Z0-9_\.\-]*, *cn=ldbm database, *cn=plugins, *cn=config",name):
                self.get_attrs(name,attrs)          
        del self.srv

    def get_attrs(self,base,attrs):
        #lame reptition but am lazy
        if re.search("cn=monitor,cn=changelog*",base):
            #entries
            changelog['currententrycachesize']= attrs['currententrycachesize'][0]
            changelog['maxentrycachesize'] = attrs['maxentrycachesize'][0]
            changelog['currententrycachecount'] = attrs['currententrycachecount'][0]
            changelog['entrycachehitratio'] = attrs['entrycachehitratio'][0]
            #DNs
            changelog['currentdncachesize']= attrs['currentdncachesize'][0]
            changelog['maxdncachesize']= attrs['maxdncachesize'][0]
            changelog['currentdncachecount'] = attrs['currentdncachecount'][0]
            changelog['dncachehitratio'] = attrs['dncachehitratio'][0]
            changelog['normalizeddncachehitratio']= attrs['normalizeddncachehitratio'][0]
            
        elif re.search("cn=monitor,cn=ipaca*",base):
            #entries
            ipaca['currententrycachesize']= attrs['currententrycachesize'][0]
            ipaca['maxentrycachesize'] = attrs['maxentrycachesize'][0]
            ipaca['currententrycachecount'] = attrs['currententrycachecount'][0]
            ipaca['entrycachehitratio'] = attrs['entrycachehitratio'][0]
            #DNs
            ipaca['currentdncachesize']= attrs['currentdncachesize'][0]
            ipaca['maxdncachesize']= attrs['maxdncachesize'][0]
            ipaca['currentdncachecount'] = attrs['currentdncachecount'][0]
            ipaca['dncachehitratio'] = attrs['dncachehitratio'][0]
            ipaca['normalizeddncachehitratio']= attrs['normalizeddncachehitratio'][0]
            
        elif re.search("cn=monitor,cn=userRoot*",base):
            #entries
            userRoot['currententrycachesize']= attrs['currententrycachesize'][0]
            userRoot['maxentrycachesize'] = attrs['maxentrycachesize'][0]
            userRoot['currententrycachecount'] = attrs['currententrycachecount'][0]
            userRoot['entrycachehitratio'] = attrs['entrycachehitratio'][0]
            #DNs
            userRoot['currentdncachesize']= attrs['currentdncachesize'][0]
            userRoot['maxdncachesize']= attrs['maxdncachesize'][0]
            userRoot['currentdncachecount'] = attrs['currentdncachecount'][0]
            userRoot['dncachehitratio'] = attrs['dncachehitratio'][0]
            userRoot['normalizeddncachehitratio']= attrs['normalizeddncachehitratio'][0]


    def process_stats(self):
        stats= {}
        dbcachesize=int(monitor['nsslapd-db-cache-size-bytes'])
        dbpages=int(monitor['nsslapd-db-pages-in-use'])
        dbcachefree=(dbcachesize-(pagesize*dbpages))
        dbfreerratio=round(100 * float(dbcachefree)/float(dbcachesize),2)
        dbpagein=int(ldbm['dbcachepagein'])
        dbpageout=int(ldbm['dbcachepageout'])
        dbcachehitratio=int(ldbm['dbcachehitratio'])
        dbpageroevict=int(monitor['nsslapd-db-page-ro-evict-rate'])
        dbpagerwevict=int(monitor['nsslapd-db-page-rw-evict-rate'])
        
        
        #userRoot
        userRoot_current_cachesize=int(userRoot['currententrycachesize'])
        userRoot_max_cachesize=int(userRoot['maxentrycachesize'])
        userRoot_current_cachecount=int(userRoot['currententrycachecount'])
        userRoot_current_dn_cachesize=int(userRoot['currentdncachesize'])
        userRoot_max_dn_cachesize=int(userRoot['maxdncachesize'])
        userRoot_current_dn_cachecount=int(userRoot['currentdncachecount'])
        userRoot_free=userRoot_max_cachesize-userRoot_current_cachesize
        userRoot_freeratio=round(100 * float(userRoot_free)/float(userRoot_max_cachesize),2)
        userRoot_avg_entry_size=int(userRoot_current_cachesize/userRoot_current_cachecount)
        userRoot_avg_dn_size=int(userRoot_current_dn_cachesize/userRoot_current_dn_cachecount)

        #ipaca
        ipaca_current_cachesize=int(ipaca['currententrycachesize'])
        ipaca_max_cachesize=int(ipaca['maxentrycachesize'])
        ipaca_current_cachecount=int(ipaca['currententrycachecount'])
        ipaca_current_dn_cachesize=int(ipaca['currentdncachesize'])
        ipaca_max_dn_cachesize=int(ipaca['maxdncachesize'])
        ipaca_current_dn_cachecount=int(ipaca['currentdncachecount'])
        ipaca_free=ipaca_max_cachesize-ipaca_current_cachesize
        ipaca_freeratio=round(100 * float(ipaca_free)/float(ipaca_max_cachesize),2)
        ipaca_avg_entry_size=int(ipaca_current_cachesize/ipaca_current_cachecount)
        ipaca_avg_dn_size=int(ipaca_current_dn_cachesize/ipaca_current_dn_cachecount)

        
        #changelog
        changelog_current_cachesize=int(changelog['currententrycachesize'])
        changelog_max_cachesize=int(changelog['maxentrycachesize'])
        changelog_current_cachecount=int(changelog['currententrycachecount'])
        changelog_current_dn_cachesize=int(changelog['currentdncachesize'])
        changelog_max_dn_cachesize=int(changelog['maxdncachesize'])
        changelog_current_dn_cachecount=int(changelog['currentdncachecount'])
        changelog_free=changelog_max_cachesize-changelog_current_cachesize
        changelog_freeratio=round(100 * float(changelog_free)/float(changelog_max_cachesize),2)
        changelog_avg_entry_size=int(changelog_current_cachesize/changelog_current_cachecount)
        changelog_avg_dn_size=int(changelog_current_dn_cachesize/changelog_current_dn_cachecount)


        stats={
              'dbcachesize': dbcachesize,
              'dbpages': dbpages,
              'dbcachefree': dbcachefree,
              'dbfreerratio': dbfreerratio,
              'dbpagein': dbpagein,
              'dbpageout': dbpageout,
              'dbcachehitratio': dbcachehitratio,
              'dbpageroevict': dbpageroevict,
              'dbpagerwevict': dbpagerwevict,
              'userRoot_current_cachesize': userRoot_current_cachesize,
              'userRoot_max_cachesize': userRoot_max_cachesize,
              'userRoot_current_cachecount': userRoot_current_cachecount,
              'userRoot_current_dn_cachesize': userRoot_current_dn_cachesize,
              'userRoot_max_dn_cachesize': userRoot_max_dn_cachesize,
              'userRoot_current_dn_cachecount': userRoot_current_dn_cachecount,
              'userRoot_free': userRoot_free,
              'userRoot_freeratio': userRoot_freeratio,
              'userRoot_avg_entry_size': userRoot_avg_entry_size,
              'userRoot_avg_dn_size': userRoot_avg_dn_size,
              'ipaca_current_cachesize': ipaca_current_cachesize,
              'ipaca_max_cachesize': ipaca_max_cachesize,
              'ipaca_current_cachecount': ipaca_current_cachecount,
              'ipaca_current_dn_cachesize': ipaca_current_dn_cachesize,
              'ipaca_max_dn_cachesize': ipaca_max_dn_cachesize,
              'ipaca_current_dn_cachecount': ipaca_current_dn_cachecount,
              'ipaca_free': ipaca_free,
              'ipaca_freeratio': ipaca_freeratio,
              'ipaca_avg_entry_size': ipaca_avg_entry_size,
              'ipaca_avg_dn_size': ipaca_avg_dn_size,
              'changelog_current_cachesize': changelog_current_cachesize,
              'changelog_max_cachesize': changelog_max_cachesize,
              'changelog_current_cachecount': changelog_current_cachecount,
              'changelog_current_dn_cachesize': changelog_current_dn_cachesize,
              'changelog_max_dn_cachesize': changelog_max_dn_cachesize,
              'changelog_current_dn_cachecount': changelog_current_dn_cachecount,
              'changelog_free': changelog_free,
              'changelog_freeratio': changelog_freeratio,
              'changelog_avg_entry_size': changelog_avg_entry_size,
              'changelog_avg_dn_size': changelog_avg_dn_size
            }
        return(stats)
        
        


def configer(config):
    global instances  
    hostname = 'localhost'
    binddn = None
    bindpw = None
    for node in config.children:
        key = node.key.lower()
        val = node.values[0]
        if key == 'hostname':
            hostname = val
        elif key == 'port':
            port = int(val)
        elif key == 'binddn':
            binddn = str(val)
        elif key == 'bindpw':
            bindpw = str(val)            
            
    instances.append({
        'hostname': hostname,
        'port': port,
        'binddn': binddn,
        'bindpw': bindpw})

def initer():
    collectd.debug('initing stuff, bla bla')



def reader(input_data=None):
    global instances
    for instance in instances:
        srv = DBStats(hostname=str(instance['hostname']),port=int(instance['port']),binddn=str(instance['binddn']),bindpw=str(instance['bindpw']))
        data = srv.process_stats()
        for key, value in data.iteritems():
            dispatch_value(key,value)
            

def dispatch_value(key, value):
    if not value:
        return
    metric = collectd.Values()
    metric.plugin = 'ipa_stats'
    metric.type = key
    metric.values = [value]
    metric.dispatch()


collectd.register_config(configer)
collectd.register_init(initer)
collectd.register_read(reader)
