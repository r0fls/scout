import apachelog
from urlparse import urlparse
from collections import Counter
from datetime import datetime, timedelta

LOG_TIMESTAMP_FORMAT = '[%d/%b/%Y:%H:%M:%S -0400]'


class Monitor(object):
    '''
    Monitors traffic from an HTTP access log (see http://www.w3.org/TR/WD-logfile.html)
    '''

    def __init__(self, log_file_location, log_format, period, alert_period, alert_threshold, max_frequent_sections):
        '''
        Constructor
        '''
        self.log_file_location = log_file_location
        self.log_file_position = 0
        self.log_cache = []
        self.parser = apachelog.parser(apachelog.formats[log_format])
        self.period = period
        self.alert_period = alert_period
        self.alert_threshold = alert_threshold
        self.alert_state = False
        self.max_frequent_sections = max_frequent_sections

    def _get_section(self, log_entry):
        request = log_entry['%r']
        url = request.split()[1]
        path_components = urlparse(url).path.split('/')
        if(len(path_components) < 3):
            #this path is too short to have a section
            return None
        #return component after first /
        return path_components[1]

    def _get_timestamp(self, log_entry):
        return datetime.strptime(log_entry['%t'], LOG_TIMESTAMP_FORMAT)

    def _within_alert_period(self, timestamp):
        return datetime.now() - timestamp < timedelta(minutes=self.alert_period)

    def _check_alert_state(self):
        self.log_cache = [entry for entry in self.log_cache if self._within_alert_period(entry[0])]
        if len(self.log_cache) > self.alert_threshold:
            print "ALERT!!!! %d requests in %d minutes" % len(self.log_cache), self.alert_period
            self.alert_state = True
        elif self.alert_state:
            self.alert_state = False
            print "Alert recovered"

    def run_monitor(self):
        with open(self.log_file_location, 'r') as log_file:
            log_file.seek(self.log_file_position)
            for line in log_file.readlines():
                log_entry = self.parser.parse(line)
                self.log_cache.append((self._get_timestamp(log_entry), self._get_section(log_entry)))
            self.log_file_position = log_file.tell()
        self._check_alert_state()
        self._display_frequent_sections()

    def _within_polling_period(self, timestamp):
        return datetime.now() - timestamp < timedelta(seconds=self.period)

    def _display_frequent_sections(self):
        sections = [log_entry[1] for log_entry in self.log_cache if self._within_polling_period(log_entry[0])]
        most_frequent_sections = Counter(sections).most_common(self.max_frequent_sections)
        print "Most Frequent Sections"
        for section in most_frequent_sections:
            print "%s: %s" % section
        print "......."
