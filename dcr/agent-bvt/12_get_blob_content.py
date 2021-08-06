import glob
import re
import sys
from time import sleep

if sys.version_info[0] == 3:
    from urllib.parse import unquote_plus
    from urllib.request import urlopen
    from html.parser import HTMLParser

elif sys.version_info[0] == 2:
    from urllib import unquote_plus
    from urllib2 import urlopen
    from HTMLParser import HTMLParser


def show_blob_content(description, key):
    config_files = glob.glob('/var/lib/waagent/ExtensionsConfig*.xml')
    if len(config_files) == 0:
        print('no extension config files found')
        sys.exit(1)

    config_files.sort()
    with open(config_files[-1], 'r') as fh:
        config = fh.readlines()

    status_line = list(filter(lambda s: key in s, config))[0]
    status_pattern = '<{0}.*>(.*\?)(.*)<.*'.format(key)
    match = re.match(status_pattern, status_line)

    if not match:
        print(description + ' not found')
        sys.exit(2)

    decoded_url = match.groups()[0]
    encoded_params = match.groups()[1].split('&amp;')
    for param in encoded_params:
        kvp = param.split('=')
        name = kvp[0]
        skip = name == 'sig'
        val = HTMLParser().unescape(unquote_plus(kvp[1])) if not skip else kvp[1]
        decoded_param = '&{0}={1}'.format(name, val)
        decoded_url += decoded_param

    print("\n{0} uri: {1}\n".format(description, decoded_url))
    status = None
    retries = 3
    while status is None:
        try:
            status = urlopen(decoded_url).read()
        except Exception as e:
            if retries > 0:
                retries -= 1
                sleep(60)
            else:
                # we are only collecting information, so do not fail the test
                status = 'Error reading {0}: {1}'.format(description, e)

    print("\n{0} content: {1}\n".format(description, status))


def main():
    show_blob_content('Status', 'StatusUploadBlob')
    show_blob_content('InVMArtifacts', 'InVMArtifactsProfileBlob')


if __name__ == "__main__":
    main()
