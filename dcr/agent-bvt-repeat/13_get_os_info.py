import platform
import sys

import distro


def get_distro():
    """
    In some distros, e.g. SUSE 15, platform.linux_distribution is present,
    but returns an empty value
    so we also try distro.linux_distribution in those cases
    """
    osinfo = []
    if hasattr(platform, 'linux_distribution'):
        osinfo = list(platform.linux_distribution(
            full_distribution_name=0,
            supported_dists=platform._supported_dists + ('alpine',)))

        # Remove trailing whitespace and quote in distro name

        osinfo[0] = osinfo[0].strip('"').strip(' ').lower()
    if not osinfo or not len(osinfo[0]):
        # platform.linux_distribution() is deprecated, the suggested option is to use distro module
        osinfo = distro.linux_distribution()

    return osinfo


def main():
    distro_ = get_distro()
    l0 = 'DISTRO_NAME = {0}'.format(distro_[0])
    l1 = 'DISTRO_VERSION = {0}'.format(distro_[1])
    l2 = 'DISTRO_CODE_NAME = {0}'.format(distro_[2])

    print(l0)
    print(l1)
    print(l2)

    print('PY_VERSION = {0}'.format(sys.version_info))
    print('PY_VERSION_MAJOR = {0}'.format(sys.version_info[0]))
    print('PY_VERSION_MINOR = {0}'.format(sys.version_info[1]))
    print('PY_VERSION_MICRO = {0}'.format(sys.version_info[2]))

    with open('/etc/waagent-distro', 'w') as fh:
        fh.write('{0}\n{1}\n{2}'.format(l0, l1, l2))


if __name__ == "__main__":
    main()
