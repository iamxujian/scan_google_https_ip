import os
import logging
import logging.config

try:
    path = os.path.join(os.environ['HOME'], 'file/prog/python/logger.conf')
    logging.config.fileConfig(path)
except:
    print('no specify configure for logger')
logger = logging.getLogger(__name__)

import scan_google_https_ip

class TestGoogleScaner(scan_google_https_ip.GoogleScaner):
    def test__detect_single_https_yes(self):
        assert self._detect_single_https('74.125.31.60')
        assert not self._detect_single_https('74.125.31.10')
    def test_detect_https(self):
        ips = ['74.125.31.60'] * 10
        for result in self.detect_https(ips):
            assert result

class TestGoogleScanerWithGithub(
        scan_google_https_ip.GoogleScanerWithGithub):
    def test_ip(self):
        count = 0
        for n, data in zip(range(10), self.ip()):
            assert data
            count += 1
        assert 0 < count
