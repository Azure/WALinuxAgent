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
from azurelinuxagent.common.future import ustr
from azurelinuxagent.common.AgentGlobals import AgentGlobals
from azurelinuxagent.common.exception import AgentError
from azurelinuxagent.common.utils import textutil
from azurelinuxagent.common.utils.flexible_version import FlexibleVersion


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
    def extensions(self):
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
        context = []  # used to keep track of the attribute that is being compared

        def compare_goal_states(first, second):
            compare_attributes(first, second, "activity_id")
            compare_attributes(first, second, "correlation_id")
            compare_attributes(first, second, "created_on_timestamp")
            # The status blob was added after version 112
            if from_vm_settings.host_ga_plugin_version > FlexibleVersion("1.0.8.112"):
                compare_attributes(first, second, "status_upload_blob")
                compare_attributes(first, second, "status_upload_blob_type")
            compare_attributes(first, second, "required_features")
            compare_attributes(first, second, "on_hold")
            compare_array(first.agent_manifests, second.agent_manifests, compare_agent_manifests, "agent_manifests")
            compare_array(first.extensions, second.extensions, compare_extensions, "extensions")

        def compare_agent_manifests(first, second):
            compare_attributes(first, second, "family")
            compare_attributes(first, second, "version")
            compare_attributes(first, second, "uris")

        def compare_extensions(first, second):
            compare_attributes(first, second, "name")
            compare_attributes(first, second, "version")
            compare_attributes(first, second, "state")
            compare_attributes(first, second, "supports_multi_config")
            compare_attributes(first, second, "manifest_uris")
            compare_array(first.settings, second.settings, compare_settings, "settings")

        def compare_settings(first, second):
            compare_attributes(first, second, "name")
            compare_attributes(first, second, "sequenceNumber")
            compare_attributes(first, second, "publicSettings")
            compare_attributes(first, second, "protectedSettings")
            compare_attributes(first, second, "certificateThumbprint")
            compare_attributes(first, second, "dependencyLevel")
            compare_attributes(first, second, "state")

        def compare_array(first, second, comparer, name):
            if len(first) != len(second):
                raise Exception("Number of items in {0} mismatch: {1} != {2}".format(name, len(first), len(second)))
            for i in range(len(first)):
                context.append("{0}[{1}]".format(name, i))
                try:
                    comparer(first[i], second[i])
                finally:
                    context.pop()

        def compare_attributes(first, second, attribute):
            context.append(attribute)
            try:
                first_value = getattr(first, attribute)
                second_value = getattr(second, attribute)

                if first_value != second_value:
                    raise Exception("[{0}] != [{1}] (Attribute: {2})".format(first_value, second_value, ".".join(context)))
            finally:
                context.pop()

        try:
            compare_goal_states(from_extensions_config, from_vm_settings)
        except Exception as exception:
            raise GoalStateMismatchError("Mismatch in Goal States [Incarnation {0}] != [Etag: {1}]: {2}".format(from_extensions_config.id, from_vm_settings.id, ustr(exception)))

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
        return []

    @property
    def extensions(self):
        return []

    def get_redacted_text(self):
        return ''
