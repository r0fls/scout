import unittest
from mock import Mock

from scout.Monitor import Monitor
from datetime import datetime


class Test(unittest.TestCase):

    def setUp(self):
        unittest.TestCase.setUp(self)
        self.monitor = Monitor(None, "common", None, None, 2, None)

    def testGetSection(self):
        self.assertEqual(self.monitor._get_section({'%r': "GET /section/ HTTP/1.1"}), "section")
        self.assertEqual(self.monitor._get_section({'%r': "GET /section/subsection HTTP/1.1"}), "section")
        self.assertEqual(self.monitor._get_section({'%r': "GET /section/?key=value HTTP/1.1"}), "section")
        self.assertEqual(self.monitor._get_section({'%r': "GET /section/#anchor HTTP/1.1"}), "section")
        self.assertEqual(self.monitor._get_section({'%r': "GET /section HTTP/1.1"}), None)
        self.assertEqual(self.monitor._get_section({'%r': "GET / HTTP/1.1"}), None)

    def testGenerateNewAlert(self):
        current_time = datetime.now()
        self.monitor.log_cache = [1, 1]
        self.monitor.alert_state = False
        self.monitor._add_alert = Mock()

        self.monitor._check_alert_state(current_time)

        self.monitor._add_alert.assert_called_with("High traffic generated an alert - hits = 2, triggered at %s" % current_time)
        self.assertTrue(self.monitor.alert_state, "Creation of alert should set monitor's alert_state to True")

    def testNoAlertGeneratedWhenAlertStateTrue(self):
        current_time = datetime.now()
        self.monitor.log_cache = [1, 1]
        self.monitor.alert_state = True

        self.monitor._check_alert_state(current_time)

        self.assertEquals([], self.monitor.alerts, "Monitors alerts should be empty")
        self.assertTrue(self.monitor.alert_state, "alert_state should remain True")

    def testNoAlertGeneratedWhenCacheSmallerThanThreshold(self):
        current_time = datetime.now()
        self.monitor.log_cache = [1]
        self.monitor.alert_state = False

        self.monitor._check_alert_state(current_time)

        self.assertEquals([], self.monitor.alerts, "Monitors alerts should be empty")
        self.assertFalse(self.monitor.alert_state, "alert_state should remain False")

    def testRecoveryMessageGeneratedWhenCacheSmallerThanThreshold(self):
        current_time = datetime.now()
        self.monitor.log_cache = [1]
        self.monitor.alert_state = True
        self.monitor._add_alert = Mock()

        self.monitor._check_alert_state(current_time)

        self.monitor._add_alert.assert_called_with("Traffic alert recovered at %s" % current_time)
        self.assertFalse(self.monitor.alert_state, "alert_state should become False")

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
