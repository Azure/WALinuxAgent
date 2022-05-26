# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and Openssl 1.0+
#
import base64
import datetime
import json
import os.path
import uuid

from azurelinuxagent.common import logger, conf
from azurelinuxagent.common.errorstate import ErrorState, ERROR_STATE_HOST_PLUGIN_FAILURE
from azurelinuxagent.common.event import WALAEventOperation, add_event
from azurelinuxagent.common.exception import HttpError, ProtocolError, ResourceGoneError
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.future import ustr, httpclient
from azurelinuxagent.common.protocol.healthservice import HealthService
from azurelinuxagent.common.protocol.extensions_goal_state import VmSettingsParseError, GoalStateSource
from azurelinuxagent.common.protocol.extensions_goal_state_factory import ExtensionsGoalStateFactory
from azurelinuxagent.common.utils import restutil, textutil, timeutil
from azurelinuxagent.common.utils.textutil import remove_bom
from azurelinuxagent.common.version import AGENT_NAME, AGENT_VERSION, PY_VERSION_MAJOR

HOST_PLUGIN_PORT = 32526

URI_FORMAT_GET_API_VERSIONS = "http://{0}:{1}/versions"
URI_FORMAT_VM_SETTINGS = "http://{0}:{1}/vmSettings"
URI_FORMAT_GET_EXTENSION_ARTIFACT = "http://{0}:{1}/extensionArtifact"
URI_FORMAT_PUT_VM_STATUS = "http://{0}:{1}/status"
URI_FORMAT_PUT_LOG = "http://{0}:{1}/vmAgentLog"
URI_FORMAT_HEALTH = "http://{0}:{1}/health"

API_VERSION = "2015-09-01"

_HEADER_CLIENT_NAME = "x-ms-client-name"
_HEADER_CLIENT_VERSION = "x-ms-client-version"
_HEADER_CORRELATION_ID = "x-ms-client-correlationid"
_HEADER_CONTAINER_ID = "x-ms-containerid"
_HEADER_DEPLOYMENT_ID = "x-ms-vmagentlog-deploymentid"
_HEADER_VERSION = "x-ms-version"
_HEADER_HOST_CONFIG_NAME = "x-ms-host-config-name"
_HEADER_ARTIFACT_LOCATION = "x-ms-artifact-location"
_HEADER_ARTIFACT_MANIFEST_LOCATION = "x-ms-artifact-manifest-location"

MAXIMUM_PAGEBLOB_PAGE_SIZE = 4 * 1024 * 1024  # Max page size: 4MB


class HostPluginProtocol(object):
    is_default_channel = False

    FETCH_REPORTING_PERIOD = datetime.timedelta(minutes=1)
    STATUS_REPORTING_PERIOD = datetime.timedelta(minutes=1)

    def __init__(self, endpoint):
        """
        NOTE: Before using the HostGAPlugin be sure to invoke GoalState.update_host_plugin_headers() to initialize
              the container id and role config name
        """
        if endpoint is None:
            raise ProtocolError("HostGAPlugin: Endpoint not provided")
        self.is_initialized = False
        self.is_available = False
        self.api_versions = None
        self.endpoint = endpoint
        self.container_id = None
        self.deployment_id = None
        self.role_config_name = None
        self.manifest_uri = None
        self.health_service = HealthService(endpoint)
        self.fetch_error_state = ErrorState(min_timedelta=ERROR_STATE_HOST_PLUGIN_FAILURE)
        self.status_error_state = ErrorState(min_timedelta=ERROR_STATE_HOST_PLUGIN_FAILURE)
        self.fetch_last_timestamp = None
        self.status_last_timestamp = None
        self._version = FlexibleVersion("0.0.0.0")  # Version 0 means "unknown"
        self._supports_vm_settings = None   # Tri-state variable: None == Not Initialized, True == Supports, False == Does Not Support
        self._supports_vm_settings_next_check = datetime.datetime.now()
        self._vm_settings_error_reporter = _VmSettingsErrorReporter()
        self._cached_vm_settings = None  # Cached value of the most recent vmSettings

        # restore the state of Fast Track
        if not os.path.exists(self._get_fast_track_state_file()):
            self._supports_vm_settings = False
            self._supports_vm_settings_next_check = datetime.datetime.now()
            self._fast_track_timestamp = timeutil.create_timestamp(datetime.datetime.min)
        else:
            self._supports_vm_settings = True
            self._supports_vm_settings_next_check = datetime.datetime.now()
            self._fast_track_timestamp = HostPluginProtocol.get_fast_track_timestamp()

    @staticmethod
    def _extract_deployment_id(role_config_name):
        # Role config name consists of: <deployment id>.<incarnation>(...)
        return role_config_name.split(".")[0] if role_config_name is not None else None

    def check_vm_settings_support(self):
        """
        Returns True if the HostGAPlugin supports the vmSettings API.
        """
        # _host_plugin_supports_vm_settings is set by fetch_vm_settings()
        if self._supports_vm_settings is None:
            _, _ = self.fetch_vm_settings()
        return self._supports_vm_settings

    def update_container_id(self, new_container_id):
        self.container_id = new_container_id

    def update_role_config_name(self, new_role_config_name):
        self.role_config_name = new_role_config_name
        self.deployment_id = self._extract_deployment_id(new_role_config_name)

    def update_manifest_uri(self, new_manifest_uri):
        self.manifest_uri = new_manifest_uri

    def ensure_initialized(self):
        if not self.is_initialized:
            self.api_versions = self.get_api_versions()
            self.is_available = API_VERSION in self.api_versions
            self.is_initialized = self.is_available
            add_event(op=WALAEventOperation.InitializeHostPlugin,
                      is_success=self.is_available)
        return self.is_available

    def get_health(self):
        """
        Call the /health endpoint
        :return: True if 200 received, False otherwise
        """
        url = URI_FORMAT_HEALTH.format(self.endpoint,
                                       HOST_PLUGIN_PORT)
        logger.verbose("HostGAPlugin: Getting health from [{0}]", url)
        response = restutil.http_get(url, max_retry=1)
        return restutil.request_succeeded(response)

    def get_api_versions(self):
        url = URI_FORMAT_GET_API_VERSIONS.format(self.endpoint,
                                                 HOST_PLUGIN_PORT)
        logger.verbose("HostGAPlugin: Getting API versions at [{0}]"
                       .format(url))
        return_val = []
        error_response = ''
        is_healthy = False
        try:
            headers = {_HEADER_CONTAINER_ID: self.container_id}
            response = restutil.http_get(url, headers)

            if restutil.request_failed(response):
                error_response = restutil.read_response_error(response)
                logger.error("HostGAPlugin: Failed Get API versions: {0}".format(error_response))
                is_healthy = not restutil.request_failed_at_hostplugin(response)
            else:
                return_val = ustr(remove_bom(response.read()), encoding='utf-8')
                is_healthy = True
        except HttpError as e:
            logger.error("HostGAPlugin: Exception Get API versions: {0}".format(e))

        self.health_service.report_host_plugin_versions(is_healthy=is_healthy, response=error_response)

        return return_val

    def get_vm_settings_request(self, correlation_id):
        url = URI_FORMAT_VM_SETTINGS.format(self.endpoint, HOST_PLUGIN_PORT)

        headers = {
            _HEADER_VERSION: API_VERSION,
           _HEADER_CONTAINER_ID: self.container_id,
           _HEADER_HOST_CONFIG_NAME: self.role_config_name,
           _HEADER_CORRELATION_ID: correlation_id
        }

        return url, headers

    def get_artifact_request(self, artifact_url, artifact_manifest_url=None):
        if not self.ensure_initialized():
            raise ProtocolError("HostGAPlugin: Host plugin channel is not available")

        if textutil.is_str_none_or_whitespace(artifact_url):
            raise ProtocolError("HostGAPlugin: No extension artifact url was provided")

        url = URI_FORMAT_GET_EXTENSION_ARTIFACT.format(self.endpoint,
                                                       HOST_PLUGIN_PORT)
        headers = {_HEADER_VERSION: API_VERSION,
                   _HEADER_CONTAINER_ID: self.container_id,
                   _HEADER_HOST_CONFIG_NAME: self.role_config_name,
                   _HEADER_ARTIFACT_LOCATION: artifact_url}

        if artifact_manifest_url is not None:
            headers[_HEADER_ARTIFACT_MANIFEST_LOCATION] = artifact_manifest_url

        return url, headers

    def report_fetch_health(self, uri, is_healthy=True, source='', response=''):

        if uri != URI_FORMAT_GET_EXTENSION_ARTIFACT.format(self.endpoint, HOST_PLUGIN_PORT):
            return

        if self.should_report(is_healthy,
                              self.fetch_error_state,
                              self.fetch_last_timestamp,
                              HostPluginProtocol.FETCH_REPORTING_PERIOD):
            self.fetch_last_timestamp = datetime.datetime.utcnow()
            health_signal = self.fetch_error_state.is_triggered() is False
            self.health_service.report_host_plugin_extension_artifact(is_healthy=health_signal,
                                                                      source=source,
                                                                      response=response)

    def report_status_health(self, is_healthy, response=''):
        if self.should_report(is_healthy,
                              self.status_error_state,
                              self.status_last_timestamp,
                              HostPluginProtocol.STATUS_REPORTING_PERIOD):
            self.status_last_timestamp = datetime.datetime.utcnow()
            health_signal = self.status_error_state.is_triggered() is False
            self.health_service.report_host_plugin_status(is_healthy=health_signal,
                                                          response=response)

    @staticmethod
    def should_report(is_healthy, error_state, last_timestamp, period):
        """
        Determine whether a health signal should be reported
        :param is_healthy: whether the current measurement is healthy
        :param error_state: the error state which is tracking time since failure
        :param last_timestamp: the last measurement time stamp
        :param period: the reporting period
        :return: True if the signal should be reported, False otherwise
        """

        if is_healthy:
            # we only reset the error state upon success, since we want to keep
            # reporting the failure; this is different to other uses of error states
            # which do not have a separate periodicity
            error_state.reset()
        else:
            error_state.incr()

        if last_timestamp is None:
            last_timestamp = datetime.datetime.utcnow() - period

        return datetime.datetime.utcnow() >= (last_timestamp + period)

    def put_vm_log(self, content):
        """
        Try to upload VM logs, a compressed zip file, via the host plugin /vmAgentLog channel.
        :param content: the binary content of the zip file to upload
        """
        if not self.ensure_initialized():
            raise ProtocolError("HostGAPlugin: HostGAPlugin is not available")

        if content is None:
            raise ProtocolError("HostGAPlugin: Invalid argument passed to upload VM logs. Content was not provided.")

        url = URI_FORMAT_PUT_LOG.format(self.endpoint, HOST_PLUGIN_PORT)
        response = restutil.http_put(url,
                                     data=content,
                                     headers=self._build_log_headers(),
                                     redact_data=True)

        if restutil.request_failed(response):
            error_response = restutil.read_response_error(response)
            raise HttpError("HostGAPlugin: Upload VM logs failed: {0}".format(error_response))

        return response

    def put_vm_status(self, status_blob, sas_url, config_blob_type=None):
        """
        Try to upload the VM status via the host plugin /status channel
        :param sas_url: the blob SAS url to pass to the host plugin
        :param config_blob_type: the blob type from the extension config
        :type status_blob: StatusBlob
        """
        if not self.ensure_initialized():
            raise ProtocolError("HostGAPlugin: HostGAPlugin is not available")

        if status_blob is None or status_blob.vm_status is None:
            raise ProtocolError("HostGAPlugin: Status blob was not provided")

        logger.verbose("HostGAPlugin: Posting VM status")
        blob_type = status_blob.type if status_blob.type else config_blob_type

        if blob_type == "BlockBlob":
            self._put_block_blob_status(sas_url, status_blob)
        else:
            self._put_page_blob_status(sas_url, status_blob)

    def _put_block_blob_status(self, sas_url, status_blob):
        url = URI_FORMAT_PUT_VM_STATUS.format(self.endpoint, HOST_PLUGIN_PORT)

        response = restutil.http_put(url,
                                     data=self._build_status_data(
                                         sas_url,
                                         status_blob.get_block_blob_headers(len(status_blob.data)),
                                         bytearray(status_blob.data, encoding='utf-8')),
                                     headers=self._build_status_headers())

        if restutil.request_failed(response):
            error_response = restutil.read_response_error(response)
            is_healthy = not restutil.request_failed_at_hostplugin(response)
            self.report_status_health(is_healthy=is_healthy, response=error_response)
            raise HttpError("HostGAPlugin: Put BlockBlob failed: {0}"
                            .format(error_response))
        else:
            self.report_status_health(is_healthy=True)
            logger.verbose("HostGAPlugin: Put BlockBlob status succeeded")

    def _put_page_blob_status(self, sas_url, status_blob):
        url = URI_FORMAT_PUT_VM_STATUS.format(self.endpoint, HOST_PLUGIN_PORT)

        # Convert the status into a blank-padded string whose length is modulo 512
        status = bytearray(status_blob.data, encoding='utf-8')
        status_size = int((len(status) + 511) / 512) * 512
        status = bytearray(status_blob.data.ljust(status_size), encoding='utf-8')

        # First, initialize an empty blob
        response = restutil.http_put(url,
                                     data=self._build_status_data(
                                         sas_url,
                                         status_blob.get_page_blob_create_headers(status_size)),
                                     headers=self._build_status_headers())

        if restutil.request_failed(response):
            error_response = restutil.read_response_error(response)
            is_healthy = not restutil.request_failed_at_hostplugin(response)
            self.report_status_health(is_healthy=is_healthy, response=error_response)
            raise HttpError("HostGAPlugin: Failed PageBlob clean-up: {0}"
                            .format(error_response))
        else:
            self.report_status_health(is_healthy=True)
            logger.verbose("HostGAPlugin: PageBlob clean-up succeeded")
        
        # Then, upload the blob in pages
        if sas_url.count("?") <= 0:
            sas_url = "{0}?comp=page".format(sas_url)
        else:
            sas_url = "{0}&comp=page".format(sas_url)

        start = 0
        end = 0
        while start < len(status):
            # Create the next page
            end = start + min(len(status) - start, MAXIMUM_PAGEBLOB_PAGE_SIZE)
            page_size = int((end - start + 511) / 512) * 512
            buf = bytearray(page_size)
            buf[0: end - start] = status[start: end]

            # Send the page
            response = restutil.http_put(url,
                                         data=self._build_status_data(
                                             sas_url,
                                             status_blob.get_page_blob_page_headers(start, end),
                                             buf),
                                         headers=self._build_status_headers())

            if restutil.request_failed(response):
                error_response = restutil.read_response_error(response)
                is_healthy = not restutil.request_failed_at_hostplugin(response)
                self.report_status_health(is_healthy=is_healthy, response=error_response)
                raise HttpError(
                    "HostGAPlugin Error: Put PageBlob bytes "
                    "[{0},{1}]: {2}".format(start, end, error_response))

            # Advance to the next page (if any)
            start = end
        
    def _build_status_data(self, sas_url, blob_headers, content=None):
        headers = []
        for name in iter(blob_headers.keys()):
            headers.append({
                'headerName': name,
                'headerValue': blob_headers[name]
            })

        data = {
            'requestUri': sas_url,
            'headers': headers
        }
        if not content is None:
            data['content'] = self._base64_encode(content)
        return json.dumps(data, sort_keys=True)
    
    def _build_status_headers(self):
        return {
            _HEADER_VERSION: API_VERSION,
            "Content-type": "application/json",
            _HEADER_CONTAINER_ID: self.container_id,
            _HEADER_HOST_CONFIG_NAME: self.role_config_name
        }

    def _build_log_headers(self):
        return {
            _HEADER_VERSION: API_VERSION,
            _HEADER_CONTAINER_ID: self.container_id,
            _HEADER_DEPLOYMENT_ID: self.deployment_id,
            _HEADER_CLIENT_NAME: AGENT_NAME,
            _HEADER_CLIENT_VERSION: AGENT_VERSION,
            _HEADER_CORRELATION_ID: str(uuid.uuid4())
        }

    def _base64_encode(self, data):
        s = base64.b64encode(bytes(data))
        if PY_VERSION_MAJOR > 2:
            return s.decode('utf-8')
        return s

    @staticmethod
    def _get_fast_track_state_file():
        # This file keeps the timestamp of the most recent goal state if it was retrieved via Fast Track
        return os.path.join(conf.get_lib_dir(), "fast_track.json")

    @staticmethod
    def _save_fast_track_state(timestamp):
        try:
            with open(HostPluginProtocol._get_fast_track_state_file(), "w") as file_:
                json.dump({"timestamp": timestamp}, file_)
        except Exception as e:
            logger.warn("Error updating the Fast Track state ({0}): {1}", HostPluginProtocol._get_fast_track_state_file(), ustr(e))

    @staticmethod
    def clear_fast_track_state():
        try:
            if os.path.exists(HostPluginProtocol._get_fast_track_state_file()):
                os.remove(HostPluginProtocol._get_fast_track_state_file())
        except Exception as e:
            logger.warn("Error clearing the current state for Fast Track ({0}): {1}", HostPluginProtocol._get_fast_track_state_file(),
                        ustr(e))

    @staticmethod
    def get_fast_track_timestamp():
        """
        Returns the timestamp of the most recent FastTrack goal state retrieved by fetch_vm_settings(), or None if the most recent
        goal state was Fabric or fetch_vm_settings() has not been invoked.
        """
        if not os.path.exists(HostPluginProtocol._get_fast_track_state_file()):
            return timeutil.create_timestamp(datetime.datetime.min)

        try:
            with open(HostPluginProtocol._get_fast_track_state_file(), "r") as file_:
                return json.load(file_)["timestamp"]
        except Exception as e:
            logger.warn("Can't retrieve the timestamp for the most recent Fast Track goal state ({0}), will assume the current time. Error: {1}",
                    HostPluginProtocol._get_fast_track_state_file(), ustr(e))
        return timeutil.create_timestamp(datetime.datetime.utcnow())

    def fetch_vm_settings(self, force_update=False):
        """
        Queries the vmSettings from the HostGAPlugin and returns an (ExtensionsGoalState, bool) tuple with the vmSettings and
        a boolean indicating if they are an updated (True) or a cached value (False).

        Raises
            * VmSettingsNotSupported if the HostGAPlugin does not support the vmSettings API
            * VmSettingsSupportStopped if the HostGAPlugin stopped supporting the vmSettings API
            * VmSettingsParseError if the HostGAPlugin returned invalid vmSettings (e.g. syntax error)
            * ResourceGoneError if the container ID and roleconfig name need to be refreshed
            * ProtocolError if the request fails for any other reason (e.g. not supported, time out, server error)
        """
        def raise_not_supported():
            try:
                if self._supports_vm_settings:
                    # The most recent goal state was delivered using FastTrack, and suddenly the HostGAPlugin does not support the vmSettings API anymore.
                    # This can happen if, for example, the VM is migrated across host nodes that are running different versions of the HostGAPlugin.
                    logger.warn("The HostGAPlugin stopped supporting the vmSettings API. If there is a pending FastTrack goal state, it will not be executed.")
                    add_event(op=WALAEventOperation.VmSettings, message="[VmSettingsSupportStopped] HostGAPlugin: {0}".format(self._version), is_success=False, log_event=False)
                    raise VmSettingsSupportStopped(self._fast_track_timestamp)
                else:
                    logger.info("HostGAPlugin {0} does not support the vmSettings API. Will not use FastTrack.", self._version)
                    add_event(op=WALAEventOperation.VmSettings, message="[VmSettingsNotSupported] HostGAPlugin: {0}".format(self._version), is_success=True)
                    raise VmSettingsNotSupported()
            finally:
                self._supports_vm_settings = False
                self._supports_vm_settings_next_check = datetime.datetime.now() + datetime.timedelta(hours=6)  # check again in 6 hours

        def format_message(msg):
            return "GET vmSettings [correlation ID: {0} eTag: {1}]: {2}".format(correlation_id, etag, msg)

        try:
            # Raise if VmSettings are not supported, but check again periodically since the HostGAPlugin could have been updated since the last check
            # Note that self._host_plugin_supports_vm_settings can be None, so we need to compare against False
            if self._supports_vm_settings == False and self._supports_vm_settings_next_check > datetime.datetime.now():
                # Raise VmSettingsNotSupported directly instead of using raise_not_supported() to avoid resetting the timestamp for the next check
                raise VmSettingsNotSupported()

            etag = None if force_update or self._cached_vm_settings is None else self._cached_vm_settings.etag
            correlation_id = str(uuid.uuid4())

            self._vm_settings_error_reporter.report_request()

            url, headers = self.get_vm_settings_request(correlation_id)
            if etag is not None:
                headers['if-none-match'] = etag
            response = restutil.http_get(url, headers=headers, use_proxy=False, max_retry=1, return_raw_response=True)

            if response.status == httpclient.GONE:
                raise ResourceGoneError()

            if response.status == httpclient.NOT_FOUND:  # the HostGAPlugin does not support FastTrack
                raise_not_supported()

            if response.status == httpclient.NOT_MODIFIED:  # The goal state hasn't changed, return the current instance
                return self._cached_vm_settings, False

            if response.status != httpclient.OK:
                error_description = restutil.read_response_error(response)
                # For historical reasons the HostGAPlugin returns 502 (BAD_GATEWAY) for internal errors instead of using
                # 500 (INTERNAL_SERVER_ERROR). We add a short prefix to the error message in the hope that it will help
                # clear any confusion produced by the poor choice of status code.
                if response.status == httpclient.BAD_GATEWAY:
                    error_description = "[Internal error in HostGAPlugin] {0}".format(error_description)
                error_description = format_message(error_description)

                if 400 <= response.status <= 499:
                    self._vm_settings_error_reporter.report_error(error_description, _VmSettingsError.ClientError)
                elif 500 <= response.status <= 599:
                    self._vm_settings_error_reporter.report_error(error_description, _VmSettingsError.ServerError)
                else:
                    self._vm_settings_error_reporter.report_error(error_description, _VmSettingsError.HttpError)

                raise ProtocolError(error_description)

            for h in response.getheaders():
                if h[0].lower() == 'etag':
                    response_etag = h[1]
                    break
            else:  # since the vmSettings were updated, the response must include an etag
                message = format_message("The vmSettings response does not include an Etag header")
                raise ProtocolError(message)

            response_content = ustr(response.read(), encoding='utf-8')

            vm_settings = ExtensionsGoalStateFactory.create_from_vm_settings(response_etag, response_content, correlation_id)

            # log the HostGAPlugin version
            if vm_settings.host_ga_plugin_version != self._version:
                self._version = vm_settings.host_ga_plugin_version
                message = "HostGAPlugin version: {0}".format(vm_settings.host_ga_plugin_version)
                logger.info(message)
                add_event(op=WALAEventOperation.HostPlugin, message=message, is_success=True)

            # Don't support HostGAPlugin versions older than 124
            if vm_settings.host_ga_plugin_version < FlexibleVersion("1.0.8.124"):
                raise_not_supported()

            self._supports_vm_settings = True
            self._cached_vm_settings = vm_settings

            if vm_settings.source == GoalStateSource.FastTrack:
                self._fast_track_timestamp = vm_settings.created_on_timestamp
                self._save_fast_track_state(vm_settings.created_on_timestamp)
            else:
                self.clear_fast_track_state()

            return vm_settings, True

        except (ProtocolError, ResourceGoneError, VmSettingsNotSupported, VmSettingsParseError):
            raise
        except Exception as exception:
            if isinstance(exception, IOError) and "timed out" in ustr(exception):
                message = format_message("Timeout")
                self._vm_settings_error_reporter.report_error(message, _VmSettingsError.Timeout)
            else:
                message = format_message("Request failed: {0}".format(textutil.format_exception(exception)))
                self._vm_settings_error_reporter.report_error(message, _VmSettingsError.RequestFailed)
            raise ProtocolError(message)
        finally:
            self._vm_settings_error_reporter.report_summary()


class VmSettingsNotSupported(TypeError):
    """
    Indicates that the HostGAPlugin does not support the vmSettings API
    """


class VmSettingsSupportStopped(VmSettingsNotSupported):
    """
    Indicates that the HostGAPlugin supported the vmSettings API in previous calls, but now it does not support it for current call.
    This can happen, for example, if the VM is migrated across nodes with different HostGAPlugin versions.
    """
    def __init__(self, timestamp):
        super(VmSettingsSupportStopped, self).__init__()
        self.timestamp = timestamp


class _VmSettingsError(object):
    ClientError    = 'ClientError'
    HttpError      = 'HttpError'
    RequestFailed  = 'RequestFailed'
    ServerError    = 'ServerError'
    Timeout        = 'Timeout'


class _VmSettingsErrorReporter(object):
    _MaxErrors = 3  # Max number of errors reported to telemetry (by period)
    _Period = datetime.timedelta(hours=1)  # How often to report the summary

    def __init__(self):
        self._reset()

    def _reset(self):
        self._request_count = 0  # Total number of vmSettings HTTP requests
        self._error_count = 0   # Total number of errors issuing vmSettings requests (includes all kinds of errors)
        self._client_error_count = 0  # Count of client side errors (HTTP status in the 400s)
        self._http_error_count = 0  # Count of HTTP errors other than 400s and 500s
        self._request_failure_count = 0  # Total count of requests that could not be issued (does not include timeouts or requests that were actually issued and failed, for example, with 500 or 400 statuses)
        self._server_error_count = 0  # Count of server side errors (HTTP status in the 500s)
        self._timeout_count = 0  # Count of timeouts on vmSettings requests
        self._next_period = datetime.datetime.now() + _VmSettingsErrorReporter._Period

    def report_request(self):
        self._request_count += 1

    def report_error(self, error, category):
        self._error_count += 1

        if self._error_count <= _VmSettingsErrorReporter._MaxErrors:
            add_event(op=WALAEventOperation.VmSettings, message="[{0}] {1}".format(category, error), is_success=True, log_event=False)

        if category == _VmSettingsError.ClientError:
            self._client_error_count += 1
        elif category == _VmSettingsError.HttpError:
            self._http_error_count += 1
        elif category == _VmSettingsError.RequestFailed:
            self._request_failure_count += 1
        elif category == _VmSettingsError.ServerError:
            self._server_error_count += 1
        elif category == _VmSettingsError.Timeout:
            self._timeout_count += 1

    def report_summary(self):
        if datetime.datetime.now() >= self._next_period:
            summary = {
                "requests":       self._request_count,
                "errors":         self._error_count,
                "serverErrors":   self._server_error_count,
                "clientErrors":   self._client_error_count,
                "timeouts":       self._timeout_count,
                "failedRequests": self._request_failure_count
            }
            message = json.dumps(summary)
            add_event(op=WALAEventOperation.VmSettingsSummary, message=message, is_success=False, log_event=False)
            if self._error_count > 0:
                logger.info("[VmSettingsSummary] {0}", message)

            self._reset()
