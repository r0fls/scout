import unittest
from scout.Monitor import Monitor


class Test(unittest.TestCase):

    def testGetSection(self):
        monitor = Monitor(None, "common", None, None, None, None)
        self.assertEqual(monitor._get_section({'%r': "GET /section HTTP/1.1"}), "section")
        self.assertEqual(monitor._get_section({'%r': "GET /section?key=value HTTP/1.1"}), "section")
        self.assertEqual(monitor._get_section({'%r': "GET /section/subsection HTTP/1.1"}), "section")
        self.assertEqual(monitor._get_section({'%r': "GET /section#anchor HTTP/1.1"}), "section")
        self.assertEqual(monitor._get_section({'%r': "GET / HTTP/1.1"}), "")


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
