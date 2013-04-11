import apachelog
from urlparse import urlparse
from collections import Counter

LOG_FILE_LOCATION = '/var/log/apache2/access_log'
APACHE_FORMAT = 'common'
NUM_COMMON_SECTIONS = 10

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
            sections = []
            for line in log_file.readlines():
                log_entry = self.parser.parse(line)
                sections.append(self.get_section(log_entry))
            self.display_frequent_sections(sections)
            self.log_file_position = log_file.tell()

    def display_frequent_sections(self, sections):
        most_frequent_sections = Counter(sections).most_common(NUM_COMMON_SECTIONS)
        print "Most Frequent Sections"
        for section in most_frequent_sections:
            print "%s: %s" % section
        print "......."
