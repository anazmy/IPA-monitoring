#!/usr/bin/python
# -*- coding: utf-8 -*-
import collectd
import ldap

instances = {}
config = None



monitorattrs = [
    'anonymousbinds',
    'unauthbinds',
    'simpleauthbinds',
    'strongauthbinds',
    'bindsecurityerrors',
    'inops',
    'readops',
    'compareops',
    'addentryops',
    'removeentryops',
    'modifyentryops',
    'modifyrdnops',
    'listops',
    'searchops',
    'onelevelsearchops',
    'wholesubtreesearchops',
    'referrals',
    'chainings',
    'securityerrors',
    'errors',
    'connections',
    'connectionseq',
    'bytesrecv',
    'bytessent',
    'entriesreturned',
    'referralsreturned',
    'masterentries',
    'copyentries',
    'cacheentries',
    'cachehits',
    'slavehits'
    ]


class LDAPStats(object):

    def __init__(
        self,
        hostname=None,
        port=389,
        binddn=None,
        bindpw=None,
        ):
        self.hostname = hostname
        self.binddn = binddn
        self.bindpw = bindpw
        self.port = int(port)
        if self.hostname != None:
            self.__get_stats__()

    def __get_stats__(self):
        self.srv = ldap.open(self.hostname, self.port)
        if self.binddn != None:
            self.srv.simple_bind_s(self.binddn, self.bindpw)
        (dn, attrs) = self.srv.search_s('cn=snmp,cn=monitor',ldap.SCOPE_BASE, attrlist=monitorattrs)[0]
        for a in monitorattrs:
            if int(attrs[a][0]) < 0:
                attrs[a][0] = int(attrs[a][0]) * -1
            setattr(self, a, int(attrs[a][0]))
        del self.srv

    def get_stats(self, hr=False):
        stats = []
        for a in monitorattrs:
            stats.append(int(getattr(self, a)))
        if hr == False:
            return stats
        else:
            return dict(zip(monitorattrs, stats))


def configer(config):
    global instances
    collectd.debug('Configuring Stuff')

    # children', 'key', 'parent', 'values'
    for c in config.children:
        if c.key == 'server':
            for srv in c.children:
                if srv.key == 'hostname':
                    hostname = '.'.join(srv.values)
                elif srv.key == 'port':
                    port = int(srv.values[0])
            instances[hostname] = port


def initer():
    collectd.debug('initing stuff')


def reader(input_data=None):
    global instances
    for h in instances:
        srv = LDAPStats(hostname=h, port=instances[h])
        data = srv.get_stats(hr=True)
        for key, value in data.iteritems():
			dispatch_value(key,value)


def dispatch_value(value_type, value):
    if not value:
        return
    metric = collectd.Values()
    metric.plugin = '389_monitorstats'
    metric.type = value_type
    metric.values = [value]
    metric.dispatch()
    


collectd.register_config(configer)
collectd.register_init(initer)
collectd.register_read(reader)
