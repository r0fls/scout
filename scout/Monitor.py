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
        self.parser = apachelog.parser(apachelog.formats[log_format])
        self.period = period
        self.alert_period = alert_period
        self.alert_threshold = alert_threshold
        self.max_frequent_sections = max_frequent_sections

        self.log_file_position = 0
        self.log_cache = []
        self.alert_state = False
        self.alerts = []

    def run_monitor(self):
        current_time = datetime.now()
        self._update_log_data(current_time)
        self._check_alert_state(current_time)
        self._display_frequent_sections(current_time)

    def _update_log_data(self, current_time):
        #Load any new data from access log file
        with open(self.log_file_location, 'r') as log_file:
            log_file.seek(self.log_file_position)
            for line in log_file.readlines():
                log = self.parser.parse(line)
                log_entry = LogEntry(self._get_timestamp(log), self._get_section(log))
                self.log_cache.append(log_entry)
            self.log_file_position = log_file.tell()
        #Remove any entries from cache that are out of the alerting period
        self.log_cache = [entry for entry in self.log_cache if self._within_alert_period(entry.timestamp, current_time)]

    def _get_timestamp(self, log_entry):
        return datetime.strptime(log_entry['%t'], LOG_TIMESTAMP_FORMAT)

    def _get_section(self, log_entry):
        request = log_entry['%r']
        url = request.split()[1]
        path_components = urlparse(url).path.split('/')
        if(len(path_components) < 3):
            #this path is too short to have a section
            return None
        #return component after first /
        return path_components[1]

    def _within_alert_period(self, timestamp, current_time):
        return current_time - timestamp < timedelta(minutes=self.alert_period)

    def _check_alert_state(self, current_time):
        if len(self.log_cache) >= self.alert_threshold:
            if not self.alert_state:
                message = "High traffic generated an alert - hits = %d, triggered at %s" % (len(self.log_cache), current_time)
                self._add_alert(message)
                self.alert_state = True
        elif self.alert_state:
            self.alert_state = False
            self._add_alert("Traffic alert recovered at %s" % current_time)

    def _add_alert(self, alert):
        self.alerts.append(alert)

    def _display_frequent_sections(self, current_time):
        sections = [log_entry.section for log_entry in self.log_cache if self._within_polling_period(log_entry.timestamp, current_time)]
        most_frequent_sections = Counter(sections).most_common(self.max_frequent_sections)
        print "Most Frequent Sections"
        for section in most_frequent_sections:
            print "%s: %s" % section
        print "......."

    def _within_polling_period(self, timestamp, current_time):
        return current_time - timestamp < timedelta(seconds=self.period)


class LogEntry(object):
    '''
    Contains an entry from a log file
    '''

    def __init__(self, timestamp, section):
        self._timestamp = timestamp
        self._section = section

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def section(self):
        return self._section
