import sys
from dungeon_crawler.scenarios_utils.distro import get_distro


def main():
    distro = get_distro()
    l0 = 'DISTRO_NAME = {0}'.format(distro[0])
    l1 = 'DISTRO_VERSION = {0}'.format(distro[1])
    l2 = 'DISTRO_CODE_NAME = {0}'.format(distro[2])

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
