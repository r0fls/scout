import apachelog
from urlparse import urlparse

LOG_FILE_LOCATION = '/var/log/apache2/access_log'
APACHE_FORMAT = 'common'

class Monitor(object):
    '''
    Monitors traffic from an HTTP access log (see http://www.w3.org/TR/WD-logfile.html)
    '''

    def __init__(self):
        '''
        Constructor
        '''
        self.log_file_position = 0
        self.parser = apachelog.parser(apachelog.formats[APACHE_FORMAT])

    def get_section(self, log_entry):
        request = log_entry['%r']
        url = request.split()[1]
        path = urlparse(url).path
        return path.split('/')[1]

    def run_monitor(self):
        with open(LOG_FILE_LOCATION, 'r') as log_file:
            log_file.seek(self.log_file_position)
            for line in log_file.readlines():
                log_entry = self.parser.parse(line)
                print self.get_section(log_entry)
            self.log_file_position = log_file.tell()
