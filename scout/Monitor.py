import apachelog
from urlparse import urlparse
from collections import Counter
from datetime import datetime, timedelta
from mako.template import Template

LOG_TIMESTAMP_FORMAT = '[%d/%b/%Y:%H:%M:%S -0400]'

CONSOLE_OUTPUT_TEMPLATE = """

=======================================================
Scout Monitor - ${timestamp}
=======================================================
% if alerts:
    % for alert in alerts:
${alert}
    % endfor
=======================================================
% endif
Frequently Requested Sections this polling period:
% for section, requests in sections:
    % if section is None:
No Section: ${requests}
    % else:
${section}: ${requests}
    % endif
% endfor
=======================================================

"""


class Monitor(object):
    '''
    Monitors traffic from an HTTP access log (see http://www.w3.org/TR/WD-logfile.html)
    '''

    def __init__(self, log_file_location, log_format, period, alert_period, alert_threshold, max_frequent_sections):
        '''
        Constructor
        '''
        self._log_file_location = log_file_location
        self._parser = apachelog.parser(apachelog.formats[log_format])
        self._period = period
        self._alert_period = alert_period
        self._alert_threshold = alert_threshold
        self._max_frequent_sections = max_frequent_sections

        self._log_file_position = 0
        self._log_cache = []
        self._alert_state = False
        self._alerts = []

    def run_monitor(self):
        current_time = datetime.now()
        self._update_log_data(current_time)
        self._check_alert_state(current_time)
        sections = self._get_frequent_sections(current_time)
        self._display_console(current_time, self._alerts, sections)

    def _update_log_data(self, current_time):
        #Load any new data from access log file
        with open(self._log_file_location, 'r') as log_file:
            log_file.seek(self._log_file_position)
            for line in log_file.readlines():
                log = self._parser.parse(line)
                log_entry = LogEntry(self._get_timestamp(log), self._get_section(log))
                self._log_cache.append(log_entry)
            self._log_file_position = log_file.tell()
        #Remove any entries from cache that are out of the alerting period
        self._log_cache = [entry for entry in self._log_cache if self._within_alert_period(entry.timestamp, current_time)]

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
        return current_time - timestamp < timedelta(minutes=self._alert_period)

    def _check_alert_state(self, current_time):
        if len(self._log_cache) >= self._alert_threshold:
            if not self._alert_state:
                message = "High traffic generated an alert - hits = %d, triggered at %s" % (len(self._log_cache), current_time)
                self._add_alert(message)
                self._alert_state = True
        elif self._alert_state:
            self._alert_state = False
            self._add_alert("Traffic alert recovered at %s" % current_time)

    def _add_alert(self, alert):
        self._alerts.append(alert)

    def _get_frequent_sections(self, current_time):
        sections = [log_entry.section for log_entry in self._log_cache if self._within_polling_period(log_entry.timestamp, current_time)]
        return Counter(sections).most_common(self._max_frequent_sections)

    def _within_polling_period(self, timestamp, current_time):
        return current_time - timestamp < timedelta(seconds=self._period)

    def _display_console(self, current_time, alerts, sections):
        print Template(CONSOLE_OUTPUT_TEMPLATE).render(timestamp=current_time,
                                                       alerts=alerts,
                                                       sections=sections)


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
