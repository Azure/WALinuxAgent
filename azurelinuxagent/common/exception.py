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

"""
Defines all exceptions
"""


class AgentError(Exception):
    """
    Base class of agent error.
    """

    def __init__(self, msg, inner=None):
        msg = u"[{0}] {1}".format(type(self).__name__, msg)
        if inner is not None:
            msg = u"{0}\nInner error: {1}".format(msg, inner)
        super(AgentError, self).__init__(msg)


class AgentConfigError(AgentError):
    """
    When configure file is not found or malformed.
    """

    def __init__(self, msg=None, inner=None):
        super(AgentConfigError, self).__init__(msg, inner)


class AgentNetworkError(AgentError):
    """
    When network is not available.
    """

    def __init__(self, msg=None, inner=None):
        super(AgentNetworkError, self).__init__(msg, inner)


class CGroupsException(AgentError):
    """
    Exception to classify any cgroups related issue.
    """

    def __init__(self, msg=None, inner=None):
        super(CGroupsException, self).__init__(msg, inner)


class ExtensionError(AgentError):
    """
    When failed to execute an extension
    """

    def __init__(self, msg=None, inner=None, code=-1):
        super(ExtensionError, self).__init__(msg, inner)
        self.code = code


class ExtensionOperationError(ExtensionError):
    """
    When the command times out or returns with a non-zero exit_code
    """

    def __init__(self, msg=None, inner=None, code=-1, exit_code=-1):
        super(ExtensionOperationError, self).__init__(msg, inner)
        self.code = code
        self.exit_code = exit_code


class ExtensionUpdateError(ExtensionError):
    """
    When failed to update an extension
    """

    def __init__(self, msg=None, inner=None, code=-1): # pylint: disable=W0235
        super(ExtensionUpdateError, self).__init__(msg, inner, code)


class ExtensionDownloadError(ExtensionError):
    """
    When failed to download and setup an extension
    """

    def __init__(self, msg=None, inner=None, code=-1): # pylint: disable=W0235
        super(ExtensionDownloadError, self).__init__(msg, inner, code)


class ProvisionError(AgentError):
    """
    When provision failed
    """

    def __init__(self, msg=None, inner=None):
        super(ProvisionError, self).__init__(msg, inner)


class ResourceDiskError(AgentError):
    """
    Mount resource disk failed
    """

    def __init__(self, msg=None, inner=None):
        super(ResourceDiskError, self).__init__(msg, inner)


class DhcpError(AgentError):
    """
    Failed to handle dhcp response
    """

    def __init__(self, msg=None, inner=None):
        super(DhcpError, self).__init__(msg, inner)


class OSUtilError(AgentError):
    """
    Failed to perform operation to OS configuration
    """

    def __init__(self, msg=None, inner=None):
        super(OSUtilError, self).__init__(msg, inner)


class ProtocolError(AgentError):
    """
    Azure protocol error
    """

    def __init__(self, msg=None, inner=None):
        super(ProtocolError, self).__init__(msg, inner)


class ProtocolNotFoundError(ProtocolError):
    """
    Azure protocol endpoint not found
    """

    def __init__(self, msg=None, inner=None): # pylint: disable=W0235
        super(ProtocolNotFoundError, self).__init__(msg, inner)


class HttpError(AgentError):
    """
    Http request failure
    """

    def __init__(self, msg=None, inner=None):
        super(HttpError, self).__init__(msg, inner)


class InvalidContainerError(HttpError):
    """
    Container id sent in the header is invalid
    """

    def __init__(self, msg=None, inner=None): # pylint: disable=W0235
        super(InvalidContainerError, self).__init__(msg, inner)


class EventError(AgentError):
    """
    Event reporting error
    """

    def __init__(self, msg=None, inner=None):
        super(EventError, self).__init__(msg, inner)


class CryptError(AgentError):
    """
    Encrypt/Decrypt error
    """

    def __init__(self, msg=None, inner=None):
        super(CryptError, self).__init__(msg, inner)


class UpdateError(AgentError):
    """
    Update Guest Agent error
    """

    def __init__(self, msg=None, inner=None):
        super(UpdateError, self).__init__(msg, inner)


class ResourceGoneError(HttpError):
    """
   The requested resource no longer exists (i.e., status code 410)
    """

    def __init__(self, msg=None, inner=None):
        if msg is None:
            msg = "Resource is gone"
        super(ResourceGoneError, self).__init__(msg, inner)


class InvalidExtensionEventError(AgentError):
    """
    Error thrown when the extension telemetry event is invalid as defined per the contract with extensions.
    """
    # Types of InvalidExtensionEventError
    MissingKeyError = "MissingKeyError"
    EmptyMessageError = "EmptyMessageError"
    OversizeEventError = "OversizeEventError"

    def __init__(self, msg=None, inner=None):
        super(InvalidExtensionEventError, self).__init__(msg, inner)


class ExtensionErrorCodes(object): # pylint: disable=R0903
    """
    Common Error codes used across by Compute RP for better understanding
    the cause and clarify common occurring errors
    """

    # Unknown Failures
    PluginUnknownFailure = -1

    # Success
    PluginSuccess = 0

    # Catch all error code.
    PluginProcessingError = 1000

    # Plugin failed to download
    PluginManifestDownloadError = 1001

    # Cannot find or load successfully the HandlerManifest.json
    PluginHandlerManifestNotFound = 1002

    # Cannot successfully serialize the HandlerManifest.json
    PluginHandlerManifestDeserializationError = 1003

    # Cannot download the plugin package
    PluginPackageDownloadFailed = 1004

    # Cannot extract the plugin form package
    PluginPackageExtractionFailed = 1005

    # Install failed
    PluginInstallProcessingFailed = 1007

    # Update failed
    PluginUpdateProcessingFailed = 1008

    # Enable failed
    PluginEnableProcessingFailed = 1009

    # Disable failed
    PluginDisableProcessingFailed = 1010

    # Extension script timed out
    PluginHandlerScriptTimedout = 1011

    # Invalid status file of the extension.
    PluginSettingsStatusInvalid = 1012

    def __init__(self):
        pass
