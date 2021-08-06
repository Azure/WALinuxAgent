import os
from junit_xml import to_xml_report_file, TestSuite, TestCase


def main():

    test_cases = [TestCase('Test1', 'some.class.name', 123.345, 'I am stdout!', 'I am stderr!')]
    ts = TestSuite("my test suite", test_cases)

    # you can also write the XML to a file and not pretty print it
    output_file = os.path.join(os.environ['BUILD_ARTIFACTSTAGINGDIRECTORY'],
                               "test-result-{0}.xml".format(os.environ['SCENARIONAME']))
    with open(output_file, 'w') as f:
        to_xml_report_file(f, [ts])


if __name__ == "__main__":
    main()
