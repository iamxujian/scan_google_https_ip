#!/usr/bin/env python
#-*- encoding: utf-8 -*-
'''
scan google https ip

author:     iamxujian@gmail.com
repositor:  https://github.com/iamxujian/scan_google_https_ip
'''
from __future__ import unicode_literals
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
logging.getLogger('requests').setLevel(logging.WARN)
logger = logging.getLogger(__name__)

import re
from datetime import datetime, timedelta

import requests
import gevent
import gevent.pool
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import create_engine, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
Base = declarative_base()

ip_domains = Table('ip_domains', Base.metadata,
        Column('ip_id', Integer, ForeignKey('ip.id')),
        Column('domain_id', Integer, ForeignKey('domain.id')),
        )

class Ip(Base):
    __tablename__ = 'ip'

    id = Column(Integer, primary_key=True, nullable=False)
    ip = Column(String(15), unique=True, nullable=False)
    available_count = Column(Integer, default=0)
    lastest_available_time = Column(DateTime)

    domains = relationship('Domain', secondary=ip_domains, backref='ips')

    def __init__(self, ip, available_count=0):
        self.ip = ip
        self.available_count = available_count

    def __repr__(self):
        return "<Ip {}: available_count={}, lastest_available_time={}, domains={}>".format(
                self.ip,
                self.available_count,
                self.lastest_available_time,
                len(self.domains))

class Domain(Base):
    __tablename__ = 'domain'

    id = Column(Integer, primary_key=True, nullable=False)
    domain = Column(String, unique=True, nullable=False)
    
    def __repr__(self):
        return "<Domain {}({})>".format(self.domain, len(self.ips))


class GoogleScaner(object):
    def __init__(self, db=None):
        self._db = db
        self._time = datetime.now()
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
                    retval = dict(ip = ip, hosts = hosts)
                    logger.debug('ip: {}, amount of hosts: {}'.format(
                        ip, len(hosts)))
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
        p = gevent.pool.Pool(50)
        tasks = p.imap_unordered(self._detect_single_https, ips)
        for w in tasks:
            if not w:
                continue
            yield w
        p.join()
    domain_blacklist = set((
            '*.googlevideo.com',
            '*.gvt1.com',
            ))
    #google_domain_r = re.compile(r'\*.appengine\.google\.com$')
    google_domain_r = re.compile(r'(\*.appengine\.google\.com|(\*\.)?google\.\w+)$')
    def analyse(self, ips, check_times=1):
        ip_collection = dict()
        for result in self.detect_https(ips):
            ip = result['ip']
            hosts = result['hosts']
            self.record_ip_hosts(ip, hosts)
            for host in hosts:
                if self.google_domain_r.match(host):
                    ip_collection[ip] = set(hosts)
                    break
        retval = ip_collection.keys()
        logger.debug('ip: {}'.format(retval))
        if len(retval) == 0:
            logger.debug('no ip')
        elif check_times > 1:
            retval = self.analyse(retval, check_times-1)
        return retval
    def record_ip_hosts(self, ip, hosts):
        db_ip = self._db.query(Ip).filter_by(ip=ip).first()
        if not db_ip:
            db_ip = Ip(ip=ip)
            self._db.add(db_ip)
        db_ip.available_count += 1
        db_ip.lastest_available_time = self._time
        db_domains = [self._db.query(Domain).filter_by(domain=e).first() or
                Domain(domain=e) for e in hosts]
        db_ip.domains = db_domains
        try:
            self._db.commit()
        except:
            self._db.rollback()
    def get_result(self):
        #data = self._db.query(Ip).filter('youtu.be' in Ip.domains).all()
        #data = self._db.query(Ip).filter(Domain.lastest_available_time=='youtu.be').all()
        t = datetime.now() - timedelta(days=7)
        data = self._db.query(Ip.ip, Ip.available_count, Ip.lastest_available_time)\
                .filter(Ip.lastest_available_time > t)\
                .order_by(Ip.available_count.desc())\
                .limit(200)\
                .all()
        [logger.debug(e) for e in data]
        return [e[0] for e in data]



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
        #connect
        engine = create_engine('sqlite:///db.sqlite3', echo=False)
        global Base
        Base.metadata.create_all(engine)
        #create a session
        Session = sessionmaker()
        Session.configure(bind=engine)
        session = Session()
        self._db_session = session
        pass
    def run(self):
        g = GoogleScanerWithGithub(self._db_session)
        # read from local html file download from
        # https://raw.githubusercontent.com/justjavac/Google-IPs/master/README.md
        #ips = g.ip('input')
        ips = g.ip()
        result = g.analyse(ips)
        result = g.get_result()
        result = sorted(result)
        logger.debug(result)
        print('result({}): {}'.format(
            len(result),
            '|'.join(result)
            ))
        logger.debug('end')

if __name__ == '__main__':
    App().run()
