import glob
import re
from html.parser import HTMLParser
from time import sleep
from urllib.parse import unquote_plus
from urllib.request import urlopen


def show_blob_content(description, key):
    config_files = glob.glob('/var/lib/waagent/ExtensionsConfig*.xml')
    if len(config_files) == 0:
        raise Exception('no extension config files found')

    config_files.sort()
    with open(config_files[-1], 'r') as fh:
        config = fh.readlines()

    status_line = list(filter(lambda s: key in s, config))[0]
    status_pattern = '<{0}.*>(.*\?)(.*)<.*'.format(key)
    match = re.match(status_pattern, status_line)

    if not match:
        raise Exception(description + ' not found')

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

    return "\n{0} content: {1}\n".format(description, status)

