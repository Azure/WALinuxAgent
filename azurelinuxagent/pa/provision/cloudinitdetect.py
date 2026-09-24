"""Module for detecting the existence of cloud-init"""

import subprocess
import azurelinuxagent.common.logger as logger

def _cloud_init_is_enabled_systemd():
    """
    Determine whether or not cloud-init is enabled on a systemd machine.

    Args:
        None

    Returns:
        bool: True if cloud-init is enabled, False if otherwise.
    """

    try:
        systemctl_output = subprocess.check_output([
            'systemctl',
            'is-enabled',
            'cloud-init-local.service'
        ], stderr=subprocess.STDOUT).decode('utf-8').replace('\n', '')

        unit_is_enabled = systemctl_output == 'enabled'
    # pylint: disable=broad-except
    except Exception as exc:
        logger.info('Unable to get cloud-init enabled status from systemctl: {0}'.format(exc))
        unit_is_enabled = False

    return unit_is_enabled

def _cloud_init_is_enabled_service():
    """
    Determine whether or not cloud-init is enabled on a non-systemd machine.

    Args:
        None

    Returns:
        bool: True if cloud-init is enabled, False if otherwise.
    """

    for service_name in ['cloud-init', 'cloudinit']:
        try:
            subprocess.check_output([
                'service',
                service_name,
                'status'
            ], stderr=subprocess.STDOUT)
            return True
        # pylint: disable=broad-except
        except Exception as exc:
            logger.info('Tried service "{0}", unable to get enabled status: {1}'.format(service_name, exc))

    return False

def cloud_init_is_enabled():
    """
    Determine whether or not cloud-init is enabled.

    Args:
        None

    Returns:
        bool: True if cloud-init is enabled, False if otherwise.
    """

    unit_is_enabled = _cloud_init_is_enabled_systemd() or _cloud_init_is_enabled_service()
    logger.info('cloud-init is enabled: {0}'.format(unit_is_enabled))

    return unit_is_enabled
