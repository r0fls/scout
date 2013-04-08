import apachelog

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

    def run_monitor(self):
        with open(LOG_FILE_LOCATION, 'r') as log_file:
            log_file.seek(self.log_file_position)
            for line in log_file.readlines():
                print self.parser.parse(line)
            self.log_file_position = log_file.tell()
