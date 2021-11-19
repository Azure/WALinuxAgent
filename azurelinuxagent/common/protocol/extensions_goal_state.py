# Microsoft Azure Linux Agent
#
# Copyright 2020 Microsoft Corporation
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
import datetime

import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion
from azurelinuxagent.common.protocol.restapi import ExtHandlerList


class GoalStateMismatchError(AgentError):
    def __init__(self, msg):
        super(GoalStateMismatchError, self).__init__(msg)


class ExtensionsGoalState(object):
    """
    ExtensionsGoalState represents the extensions information in the goal state; that information can originate from
    ExtensionsConfig when the goal state is retrieved from the WireServe or from vmSettings when it is retrieved from
    the HostGAPlugin.

    NOTE: This is an abstract class. The corresponding concrete classes can be instantiated using the ExtensionsGoalStateFactory.
    """
    @property
    def id(self):
        """
        Returns the incarnation number if the ExtensionsGoalState was created from ExtensionsConfig, or the etag if it
        was created from vmSettings.
        """
        raise NotImplementedError()

    @property
    def activity_id(self):
        raise NotImplementedError()

    @property
    def correlation_id(self):
        raise NotImplementedError()

    @property
    def created_on_timestamp(self):
        raise NotImplementedError()

    @property
    def status_upload_blob(self):
        raise NotImplementedError()

    @property
    def status_upload_blob_type(self):
        raise NotImplementedError()

    def _set_status_upload_blob_type(self, value):
        raise NotImplementedError()

    @property
    def required_features(self):
        raise NotImplementedError()

    @property
    def on_hold(self):
        raise NotImplementedError()

    @property
    def agent_manifests(self):
        raise NotImplementedError()

    @property
    def ext_handlers(self):
        raise NotImplementedError()

    def get_redacted_text(self):
        """
        Returns the raw text (either the ExtensionsConfig or the vmSettings) with any confidential data removed, or an empty string for empty goal states.
        """
        raise NotImplementedError()

    @staticmethod
    def compare(from_extensions_config, from_vm_settings):
        """
        Compares the two instances given as argument and logs a GoalStateMismatch message if they are different.

        NOTE: The order of the two instances is important for the debug info to be logged correctly (ExtensionsConfig first, vmSettings second)
        """
        def compare_attribute(attribute):
            from_extensions_config_value = getattr(from_extensions_config, attribute)
            from_vm_settings_value = getattr(from_vm_settings, attribute)

            if from_extensions_config_value != from_vm_settings_value:
                message = "Mismatch in ExtensionsConfig (incarnation {0}) and vmSettings (etag {1}).\nAttribute: {2}()\n{3} != {4}".format(
                    from_extensions_config.id, from_vm_settings.id,
                    attribute,
                    from_extensions_config_value, from_vm_settings_value
                )
                raise GoalStateMismatchError(message)

        compare_attribute("activity_id")
        compare_attribute("correlation_id")
        compare_attribute("created_on_timestamp")
        # The status blob was added after version 112
        if from_vm_settings.host_ga_plugin_version > FlexibleVersion("1.0.8.112"):
            compare_attribute("status_upload_blob")
            compare_attribute("status_upload_blob_type")
        compare_attribute("required_features")
        compare_attribute("on_hold")
        compare_attribute("agent_manifests")

    def _do_common_validations(self):
        """
        Does validations common to vmSettings and ExtensionsConfig
        """
        if self.status_upload_blob_type not in ["BlockBlob", "PageBlob"]:
            logger.info("Status Blob type '{0}' is not valid, assuming BlockBlob", self.status_upload_blob)
            self._set_status_upload_blob_type("BlockBlob")

    @staticmethod
    def _ticks_to_utc_timestamp(ticks_string):
        """
        Takes 'ticks', a string indicating the number of ticks since midnight 0001-01-01 00:00:00, and
        returns a UTC timestamp  (every tick is 1/10000000 of a second).
        """
        minimum = datetime.datetime(1900, 1, 1, 0, 0)  # min value accepted by datetime.strftime()
        as_date_time = minimum
        if ticks_string not in (None, ""):
            try:
                as_date_time = datetime.datetime.min + datetime.timedelta(seconds=float(ticks_string) / 10 ** 7)
            except Exception as exception:
                logger.verbose("Can't parse ticks: {0}", textutil.format_exception(exception))
        as_date_time = max(as_date_time, minimum)

        return as_date_time.strftime(logger.Logger.LogTimeFormatInUTC)

    @staticmethod
    def _string_to_id(id_string):
        """
        Takes 'id', a string indicating an ID, and returns a null GUID if the string is None or empty; otherwise
        return 'id' unchanged
        """
        if id_string in (None, ""):
            return AgentGlobals.GUID_ZERO
        return id_string


class EmptyExtensionsGoalState(ExtensionsGoalState):
    def __init__(self):
        self._agent_manifests = []
        self._ext_handlers = ExtHandlerList()

    @property
    def id(self):
        return self._string_to_id(None)

    @property
    def activity_id(self):
        return AgentGlobals.GUID_ZERO

    @property
    def correlation_id(self):
        return AgentGlobals.GUID_ZERO

    @property
    def created_on_timestamp(self):
        return datetime.datetime.min

    @property
    def status_upload_blob(self):
        return None

    @property
    def status_upload_blob_type(self):
        return None

    def _set_status_upload_blob_type(self, value):
        raise TypeError("EmptyExtensionsGoalState is immutable; cannot change the value of the status upload blob")

    @property
    def required_features(self):
        return []

    @property
    def on_hold(self):
        return False

    @property
    def agent_manifests(self):
        return self._agent_manifests

    @property
    def ext_handlers(self):
        return self._ext_handlers

    def get_redacted_text(self):
        return ''
