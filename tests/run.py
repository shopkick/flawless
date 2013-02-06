import os
import os.path
import unittest


def run():
  test_files = list()
  for base, _, files in os.walk('.'):
    for filename in files:
      if filename.endswith(".py") and "test" in filename:
        test_files.append(os.path.normpath(os.path.join(base, filename)))

  module_strings = [path[0:-3].replace('/', '.') for path in test_files]
  suites = [unittest.defaultTestLoader.loadTestsFromName(modpath) for modpath
            in module_strings]
  testSuite = unittest.TestSuite(suites)
  text_runner = unittest.TextTestRunner().run(testSuite)


if __name__ == '__main__':
  run()
