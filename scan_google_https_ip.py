#!/usr/bin/env python
#-*- encoding: utf-8 -*-
'''
scan google https ip

author:     iamxujian@gmail.com
repositor:  https://github.com/iamxujian/scan_google_https_ip
'''
import gevent.monkey
gevent.monkey.patch_socket()
gevent.monkey.patch_ssl()
import os
import logging
import logging.config

try:
    path = os.path.join(os.environ['HOME'], 'file/prog/python/logger.conf')
    logging.config.fileConfig(path)
except:
    print('no specify configure for logger')
logger = logging.getLogger(__name__)

import re

import requests
import gevent
import gevent.pool

class GoogleScaner(object):
    def ip(self, *args, **kwargs):
        ''' generator for ips of google '''
        logger.debug('generate ip')
        for ip in ('74.125.31.60', '74.125.31.61'):
            yield ip
    host_r = re.compile(r'\'[^\' ]+\'')
    def _detect_single_https(self, ip):
        ''' detect the domain of ip '''
        retval = None
        try:
            requests.get('https://'+ip, timeout=1)
        except requests.exceptions.SSLError, e:
            try:
                hosts = self.host_r.findall(str(e.message))
                hosts = [e[1:-1] for e in hosts[1:]]
                if len(hosts) != 0:
                    logger.debug('{} => {}({})'.format(
                        ip, hosts[:5], len(hosts)))
                    retval = dict(ip = ip, hosts = hosts)
                #else:
                #    logger.debug('{}: {}'.format(ip, err.message))
            except Exception, e:
                logger.exception()
        except requests.exceptions.ConnectionError, e:
            pass
        except requests.exceptions.Timeout, e:
            pass
        except Exception, e:
            logger.exception('{}: {}'.format(type(e), e))
        return retval
    def detect_https(self, ips):
        if not ips:
            ips = self.ip()
        p = gevent.pool.Pool(100)
        tasks = p.imap_unordered(self._detect_single_https, ips)
        for w in tasks:
            if not w:
                continue
            logger.info('detect result: {}'.format(w))
            yield w
        p.join()
    domain_blacklist = set((
            '*.googlevideo.com',
            '*.gvt1.com',
            ))
    google_domain_r = re.compile(r'\*.appengine\.google\.com$')
    def analyse(self, ips, check_times=4):
        ip_collection = dict()
        for result in self.detect_https(ips):
            ip = result['ip']
            hosts = result['hosts']
            for host in hosts:
                if self.google_domain_r.match(host):
                    ip_collection[ip] = set(hosts)
                    break
        retval = ip_collection.keys()
        logger.debug('ip: {}'.format(retval))
        if check_times > 1:
            retval = self.analyse(retval, check_times-1)
            logger.debug('ip: {}'.format(retval))
        return retval


class GoogleScanerWithGithub(GoogleScaner):
    def ip(self, local_html=None, *args, **kwargs):
        ip_r = re.compile(r'target="_blank">(?P<ip>[0-9.]+)')
        if local_html:
            with open(local_html) as f:
                data = f.read()
        else:
            r = requests.get('https://raw.githubusercontent.com/justjavac/Google-IPs/master/README.md')
            data = r.text
        for line in data.split('\n'):
            m = ip_r.search(line)
            if m:
                ip = m.group('ip')
                yield ip

class App:
    def __init__(self):
        pass
    def run(self):
        logger.debug('run')
        g = GoogleScanerWithGithub()
        # read from local html file download from
        # https://raw.githubusercontent.com/justjavac/Google-IPs/master/README.md
        #ips = g.ip('input')
        ips = g.ip()
        result = g.analyse(ips)
        result = sorted(result)
        print('result({}): {}'.format(
            len(result),
            '|'.join(result)
            ))
        logger.debug('end')

if __name__ == '__main__':
    App().run()
