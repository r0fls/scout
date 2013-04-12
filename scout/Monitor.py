import apachelog
from urlparse import urlparse
from collections import Counter
from datetime import datetime, timedelta

LOG_FILE_LOCATION = '/var/log/apache2/access_log'
LOG_FORMAT = 'common'
FREQUENT_SECTIONS_LIMIT = 10
LOG_TIMESTAMP_FORMAT = '[%d/%b/%Y:%H:%M:%S -0400]'
POLLING_PERIOD_SECONDS = 10
ALERT_PERIOD_MINUTES = 2
ALERT_TRAFFIC_THRESHOLD = 3


class Monitor(object):
    '''
    Monitors traffic from an HTTP access log (see http://www.w3.org/TR/WD-logfile.html)
    '''

    def __init__(self):
        '''
        Constructor
        '''
        self.log_file_position = 0
        self.parser = apachelog.parser(apachelog.formats[LOG_FORMAT])
        self.log_cache = []
        self.alert_state = False

    def get_section(self, log_entry):
        request = log_entry['%r']
        url = request.split()[1]
        path = urlparse(url).path
        return path.split('/')[1]

    def get_timestamp(self, log_entry):
        return datetime.strptime(log_entry['%t'], LOG_TIMESTAMP_FORMAT)

    def within_alert_period(self, timestamp):
        return datetime.now() - timestamp < timedelta(minutes=ALERT_PERIOD_MINUTES)

    def check_alert_state(self):
        self.log_cache = [entry for entry in self.log_cache if self.within_alert_period(entry[0])]
        if len(self.log_cache) > ALERT_TRAFFIC_THRESHOLD:
            print "ALERT!!!! %d requests in %d minutes" % len(self.log_cache), ALERT_PERIOD_MINUTES
            self.alert_state = True
        elif self.alert_state:
            self.alert_state = False
            print "Alert recovered"

    def run_monitor(self):
        with open(LOG_FILE_LOCATION, 'r') as log_file:
            log_file.seek(self.log_file_position)
            for line in log_file.readlines():
                log_entry = self.parser.parse(line)
                self.log_cache.append((self.get_timestamp(log_entry), self.get_section(log_entry)))
            self.log_file_position = log_file.tell()
        self.check_alert_state()
        self.display_frequent_sections()

    def within_polling_period(self, timestamp):
        return datetime.now() - timestamp < timedelta(seconds=POLLING_PERIOD_SECONDS)

    def display_frequent_sections(self):
        sections = [log_entry[1] for log_entry in self.log_cache if self.within_polling_period(log_entry[0])]
        most_frequent_sections = Counter(sections).most_common(FREQUENT_SECTIONS_LIMIT)
        print "Most Frequent Sections"
        for section in most_frequent_sections:
            print "%s: %s" % section
        print "......."
