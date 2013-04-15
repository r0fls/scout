from setuptools import setup, find_packages

setup(name = "scout",
      version = "0.1",
      packages = find_packages(),
      install_requires = ['apachelog'],
      test_suite = "scout.test",
      tests_require = ['mock'],
      entry_points = {'console_scripts': ['scout = scout.runner:run']}
      )
