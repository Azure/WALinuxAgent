import re

from azurelinuxagent.common.utils import restutil


class HttpRequestPredicates(object):
    """
    Utility functions to check the urls used by tests
    """
    @staticmethod
    def is_goal_state_request(url):
        return url.lower() == 'http://{0}/machine/?comp=goalstate'.format(restutil.KNOWN_WIRESERVER_IP)

    @staticmethod
    def is_telemetry_request(url):
        return url.lower() == 'http://{0}/machine?comp=telemetrydata'.format(restutil.KNOWN_WIRESERVER_IP)

    @staticmethod
    def is_health_service_request(url):
        return url.lower() == 'http://{0}:80/healthservice'.format(restutil.KNOWN_WIRESERVER_IP)

    @staticmethod
    def is_in_vm_artifacts_profile_request(url):
        return re.match(r'https://.+\.blob\.core\.windows\.net/\$system/.+\.(vmSettings|settings)\?.+', url) is not None

    @staticmethod
    def _get_host_plugin_request_artifact_location(url, request_kwargs):
        if 'headers' not in request_kwargs:
            raise ValueError('Host plugin request is missing HTTP headers ({0})'.format(url))
        headers = request_kwargs['headers']
        if 'x-ms-artifact-location' not in headers:
            raise ValueError('Host plugin request is missing the x-ms-artifact-location header ({0})'.format(url))
        return headers['x-ms-artifact-location']

    @staticmethod
    def is_host_plugin_vm_settings_request(url):
        return url.lower() == 'http://{0}:{1}/vmsettings'.format(restutil.KNOWN_WIRESERVER_IP, restutil.HOST_PLUGIN_PORT)

    @staticmethod
    def is_host_plugin_health_request(url):
        return url.lower() == 'http://{0}:{1}/health'.format(restutil.KNOWN_WIRESERVER_IP, restutil.HOST_PLUGIN_PORT)

    @staticmethod
    def is_host_plugin_extension_artifact_request(url):
        return url.lower() == 'http://{0}:{1}/extensionartifact'.format(restutil.KNOWN_WIRESERVER_IP, restutil.HOST_PLUGIN_PORT)

    @staticmethod
    def is_host_plugin_status_request(url):
        return url.lower() == 'http://{0}:{1}/status'.format(restutil.KNOWN_WIRESERVER_IP, restutil.HOST_PLUGIN_PORT)

    @staticmethod
    def is_host_plugin_extension_request(request_url, request_kwargs, extension_url):
        if not HttpRequestPredicates.is_host_plugin_extension_artifact_request(request_url):
            return False
        artifact_location = HttpRequestPredicates._get_host_plugin_request_artifact_location(request_url, request_kwargs)
        return artifact_location == extension_url

    @staticmethod
    def is_host_plugin_in_vm_artifacts_profile_request(url, request_kwargs):
        if not HttpRequestPredicates.is_host_plugin_extension_artifact_request(url):
            return False
        artifact_location = HttpRequestPredicates._get_host_plugin_request_artifact_location(url, request_kwargs)
        return HttpRequestPredicates.is_in_vm_artifacts_profile_request(artifact_location)

    @staticmethod
    def is_host_plugin_put_logs_request(url):
        return url.lower() == 'http://{0}:{1}/vmagentlog'.format(restutil.KNOWN_WIRESERVER_IP,
                                                                 restutil.HOST_PLUGIN_PORT)

    @staticmethod
    def is_agent_package_request(url):
        return re.match(r"^http://mock-goal-state/ga-manifests/OSTCExtensions.WALinuxAgent__([\d.]+)$", url) is not None

    @staticmethod
    def is_ga_manifest_request(url):
        return "manifest_of_ga.xml" in url
