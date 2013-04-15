import apachelog
from urlparse import urlparse
from collections import Counter
from datetime import datetime, timedelta
from mako.template import Template

LOG_TIMESTAMP_FORMAT = '[%d/%b/%Y:%H:%M:%S -0400]'

CONSOLE_OUTPUT_TEMPLATE = """

====================================================================================
Scout Monitor - ${timestamp}
====================================================================================
% if alerts:
    % for alert in alerts:
${alert}
    % endfor
====================================================================================
% endif
Number of requests: ${num_requests}

Most frequently requested sections this polling period:
% for section, requests in sections:
    % if section is None:
No Section: ${requests}
    % else:
${section}: ${requests}
    % endif
% endfor

Most frequently returned status codes this polling period:
% for response_code, requests in response_codes:
${response_code}: ${requests}
% endfor
====================================================================================

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
        log_entries = self._get_polling_period_entries(current_time)
        sections = self._get_frequent_sections(log_entries)
        response_codes = self._get_frequent_response_codes(log_entries)
        self._display_console(current_time, self._alerts, len(log_entries), sections, response_codes)

    def _update_log_data(self, current_time):
        #Load any new data from access log file
        with open(self._log_file_location, 'r') as log_file:
            log_file.seek(self._log_file_position)
            for line in log_file.readlines():
                log_line = self._parser.parse(line)
                log_entry = LogEntry(self._get_timestamp(log_line),
                                     self._get_section(log_line),
                                     self._get_response_code(log_line))
                self._log_cache.append(log_entry)
            self._log_file_position = log_file.tell()
        #Remove any entries from cache that are out of the alerting period
        self._log_cache = [entry for entry in self._log_cache if self._within_alert_period(entry.timestamp, current_time)]

    def _get_timestamp(self, log_line):
        return datetime.strptime(log_line['%t'], LOG_TIMESTAMP_FORMAT)

    def _get_section(self, log_line):
        request = log_line['%r']
        url = request.split()[1]
        path_components = urlparse(url).path.split('/')
        if(len(path_components) < 3):
            #this path is too short to have a section
            return None
        #return component after first /
        return path_components[1]

    def _get_response_code(self, log_line):
        return log_line['%>s']

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

    def _get_polling_period_entries(self, current_time):
        return [log_entry for log_entry in self._log_cache if self._within_polling_period(log_entry.timestamp, current_time)]

    def _within_polling_period(self, timestamp, current_time):
        return current_time - timestamp < timedelta(seconds=self._period)

    def _get_frequent_sections(self, log_entries):
        sections = [log_entry.section for log_entry in log_entries]
        return Counter(sections).most_common(self._max_frequent_sections)

    def _get_frequent_response_codes(self, log_entries):
        response_codes = [log_entry.response_code for log_entry in log_entries]
        return Counter(response_codes).most_common()

    def _display_console(self, current_time, alerts, num_requests, sections, response_codes):
        print Template(CONSOLE_OUTPUT_TEMPLATE).render(timestamp=current_time,
                                                       alerts=alerts,
                                                       num_requests=num_requests,
                                                       sections=sections,
                                                       response_codes=response_codes)


class LogEntry(object):
    '''
    Contains an entry from a log file
    '''

    def __init__(self, timestamp, section, response_code):
        self._timestamp = timestamp
        self._section = section
        self._response_code = response_code

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def section(self):
        return self._section

    @property
    def response_code(self):
        return self._response_code
