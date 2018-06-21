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

import errno
import os
import re
import time

from azurelinuxagent.common import logger
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil
from azurelinuxagent.common.version import AGENT_NAME, CURRENT_VERSION


BASE_CGROUPS = '/sys/fs/cgroup'
WRAPPER_CGROUP_NAME = "Agent+Extensions"
METRIC_HIERARCHIES = ['cpu', 'memory']
MEMORY_DEFAULT = -1

re_user_system_times = re.compile('user (\d+)\nsystem (\d+)\n')

related_services = {
    "Microsoft.OSTCExtensions.LinuxDiagnostic":    ["omid", "omsagent-LAD", "mdsd-lde"],
    "Microsoft.Azure.Diagnostics.LinuxDiagnostic": ["omid", "omsagent-LAD", "mdsd-lde"],
}


class CGroupsException(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)


# The metric classes (Cpu, Memory, etc) can all assume that CGroups is enabled, as the CGroupTelemetry
# class is very careful not to call them if CGroups isn't enabled. Any tests should be disabled if the osutil
# is_cgroups_support() method returns false.


class Cpu(object):
    def __init__(self, cgt):
        """
        Initialize data collection for the Cpu hierarchy. User must call update() before attempting to get
        any useful metrics.

        :param cgt: CGroupsTelemetry
        :return:
        """
        self.cgt = cgt
        self.osutil = get_osutil()
        self.current_cpu_total = self.get_current_cpu_total()
        self.previous_cpu_total = 0
        self.current_system_cpu = self.osutil.get_total_cpu_ticks_since_boot()
        self.previous_system_cpu = 0

    def __str__(self):
        return "Cgroup: Current {0}, previous {1}; System: Current {2}, previous {3}".format(
            self.current_cpu_total, self.previous_cpu_total, self.current_system_cpu, self.previous_system_cpu
        )

    def get_current_cpu_total(self):
        """
        Compute the number of USER_HZ of CPU time (user and system) consumed by this cgroup since boot.

        :return: int
        """
        cpu_total = 0
        try:
            cpu_stat = self.cgt.cgroup.get_file_contents('cpu', 'cpuacct.stat')
            if cpu_stat is not None:
                m = re_user_system_times.match(cpu_stat)
                if m:
                    cpu_total = int(m.groups()[0]) + int(m.groups()[1])
        except CGroupsException:
            # There are valid reasons for file contents to be unavailable; for example, if an extension
            # has not yet started (or has stopped) an associated service on a VM using systemd, the cgroup for
            # the service will not exist ('cause systemd will tear it down). This might be a transient or a
            # long-lived state, so there's no point in logging it, much less emitting telemetry.
            pass
        return cpu_total

    def update(self):
        """
        Update all raw data required to compute metrics of interest. The intent is to call update() once, then
        call the various get_*() methods which use this data, which we've collected exactly once.
        """
        self.previous_cpu_total = self.current_cpu_total
        self.previous_system_cpu = self.current_system_cpu
        self.current_cpu_total = self.get_current_cpu_total()
        self.current_system_cpu = self.osutil.get_total_cpu_ticks_since_boot()

    def get_cpu_percent(self):
        """
        Compute the percent CPU time used by this cgroup over the elapsed time since the last time this instance was
        update()ed.  If the cgroup fully consumed 2 cores on a 4 core system, return 200.

        :return: CPU usage in percent of a single core
        :rtype: float
        """
        cpu_delta = self.current_cpu_total - self.previous_cpu_total
        system_delta = max(1, self.current_system_cpu - self.previous_system_cpu)

        return round(float(cpu_delta * self.cgt.cpu_count * 100) / float(system_delta), 3)

    def collect(self):
        """
        Collect and return a list of all cpu metrics. If no metrics are collected, return an empty list.

        :rtype: [(str, str, float)]
        """
        self.update()
        usage = self.get_cpu_percent()
        return [("Process", "% Processor Time", usage)]


class Memory(object):
    def __init__(self, cgt):
        """
        Initialize data collection for the Memory hierarchy

        :param CGroupsTelemetry cgt: The telemetry object for which memory metrics should be collected
        :return:
        """
        self.cgt = cgt

    def get_memory_usage(self):
        """
        Collect memory.usage_in_bytes from the cgroup.

        :return: Memory usage in bytes
        :rtype: int
        """
        usage = self.cgt.cgroup.get_parameter('memory', 'memory.usage_in_bytes')
        if not usage:
            usage = "0"
        return int(usage)

    def collect(self):
        """
        Collect and return a list of all memory metrics

        :rtype: [(str, str, float)]
        """
        usage = self.get_memory_usage()
        return [("Memory", "Total Memory Usage", usage)]


class CGroupsTelemetry(object):
    """
    Encapsulate the cgroup-based telemetry for the agent or one of its extensions, or for the aggregation across
    the agent and all of its extensions. These objects should have lifetimes that span the time window over which
    measurements are desired; in general, they're not terribly effective at providing instantaneous measurements.
    """
    _tracked = {}
    _metrics = {
        "cpu": Cpu,
        "memory": Memory
    }
    _hierarchies = list(_metrics.keys())
    tracked_names = set()

    @staticmethod
    def metrics_hierarchies():
        return CGroupsTelemetry._hierarchies

    @staticmethod
    def track_cgroup(cgroup):
        """
        Create a CGroupsTelemetry object to track a particular CGroups instance. Typical usage:
        1) Create a CGroups object
        2) Ask CGroupsTelemetry to track it
        3) Tell the CGroups object to add one or more processes (or let systemd handle that, for its cgroups)

        :param CGroups cgroup: The cgroup to track
        """
        name = cgroup.name
        if CGroups.enabled() and not CGroupsTelemetry.is_tracked(name):
            tracker = CGroupsTelemetry(name, cgroup=cgroup)
            CGroupsTelemetry._tracked[name] = tracker

    @staticmethod
    def track_systemd_service(name):
        """
        If not already tracking it, create the CGroups object for a systemd service and track it.

        :param str name: Service name (without .service suffix) to be tracked.
        """
        service_name = "{0}.service".format(name).lower()
        if CGroups.enabled() and not CGroupsTelemetry.is_tracked(service_name):
            cgroup = CGroups.for_systemd_service(service_name)
            tracker = CGroupsTelemetry(service_name, cgroup=cgroup)
            CGroupsTelemetry._tracked[service_name] = tracker

    @staticmethod
    def track_extension(name, cgroup=None):
        """
        Create all required CGroups to track all metrics for an extension and its associated services.

        :param str name: Full name of the extension to be tracked
        :param CGroups cgroup: CGroup for the extension itself. This method will create it if none is supplied.
        """
        if not CGroups.enabled():
            return

        if not CGroupsTelemetry.is_tracked(name):
            cgroup = CGroups.for_extension(name) if cgroup is None else cgroup
            logger.info("Now tracking cgroup {0}".format(name))
            CGroupsTelemetry.track_cgroup(cgroup)
        if CGroups.is_systemd_manager():
            if name in related_services:
                for service_name in related_services[name]:
                    CGroupsTelemetry.track_systemd_service(service_name)

    @staticmethod
    def track_agent():
        """
        Create and track the correct cgroup for the agent itself. The actual cgroup depends on whether systemd
        is in use, but the caller doesn't need to know that.
        """
        if not CGroups.enabled():
            return
        if CGroups.is_systemd_manager():
            CGroupsTelemetry.track_systemd_service(AGENT_NAME)
        else:
            CGroupsTelemetry.track_cgroup(CGroups.for_extension(AGENT_NAME))

    @staticmethod
    def is_tracked(name):
        return name in CGroupsTelemetry._tracked

    @staticmethod
    def stop_tracking(name):
        """
        Stop tracking telemetry for the CGroups associated with an extension. If any system services are being
        tracked, those will continue to be tracked; multiple extensions might rely upon the same service.

        :param str name: Extension to be dropped from tracking
        """
        if CGroupsTelemetry.is_tracked(name):
            del (CGroupsTelemetry._tracked[name])

    @staticmethod
    def collect_all_tracked():
        """
        Return a dictionary mapping from the name of a tracked cgroup to the list of collected metrics for that cgroup.
        Collecting metrics is not guaranteed to be a fast operation; it's possible some other thread might add or remove
        tracking for a cgroup while we're doing it. To avoid "dictionary changed size during iteration" exceptions,
        work from a shallow copy of the _tracked dictionary.

        :returns: Dictionary of list collected metrics (metric class, metric name, value), by cgroup
        :rtype: dict(str: [(str, str, float)])
        """
        results = {}
        for cgroup_name, collector in CGroupsTelemetry._tracked.copy().items():
            cgroup_name = cgroup_name if cgroup_name else WRAPPER_CGROUP_NAME
            results[cgroup_name] = collector.collect()
        return results

    @staticmethod
    def update_tracked(ext_handlers):
        """
        Track CGroups for all enabled extensions.
        Track CGroups for services created by enabled extensions.
        Stop tracking CGroups for not-enabled extensions.

        :param List(ExtHandler) ext_handlers:
        """
        if not CGroups.enabled():
            return

        not_enabled_extensions = set()
        for extension in ext_handlers:
            if extension.properties.state == u"enabled":
                CGroupsTelemetry.track_extension(extension.name)
            else:
                not_enabled_extensions.add(extension.name)

        names_now_tracked = set(CGroupsTelemetry._tracked.keys())
        if CGroupsTelemetry.tracked_names != names_now_tracked:
            now_tracking = " ".join("[{0}]".format(name) for name in sorted(names_now_tracked))
            if len(now_tracking):
                logger.info("After updating cgroup telemetry, tracking {0}".format(now_tracking))
            else:
                logger.warn("After updating cgroup telemetry, tracking no cgroups.")
            CGroupsTelemetry.tracked_names = names_now_tracked

    def __init__(self, name, cgroup=None):
        """
        Create the necessary state to collect metrics for the agent, one of its extensions, or the aggregation across
        the agent and all of its extensions. To access aggregated metrics, instantiate this object with an empty string
        or None.

        :param name: str
        """
        if name is None:
            name = ""
        self.name = name
        if cgroup is None:
            cgroup = CGroups.for_extension(name)
        self.cgroup = cgroup
        self.cpu_count = CGroups.get_num_cores()
        self.current_wall_time = time.time()
        self.previous_wall_time = 0

        self.data = {}
        if CGroups.enabled():
            for hierarchy in CGroupsTelemetry.metrics_hierarchies():
                self.data[hierarchy] = CGroupsTelemetry._metrics[hierarchy](self)

    def collect(self):
        """
        Return a list of collected metrics. Each element is a tuple of
        (metric group name, metric name, metric value)
        :return: [(str, str, float)]
        """
        results = []
        for collector in self.data.values():
            results.extend(collector.collect())
        return results


class CGroups(object):
    """
    This class represents the cgroup folders for the agent or an extension. This is a pretty lightweight object
    without much state worth preserving; it's not unreasonable to create one just when you need it.
    """
    # whether cgroup support is enabled
    _enabled = True
    _hierarchies = CGroupsTelemetry.metrics_hierarchies()
    _use_systemd = None     # Tri-state: None (i.e. "unknown"), True, False
    _osutil = get_osutil()

    @staticmethod
    def _construct_custom_path_for_hierarchy(hierarchy, cgroup_name):
        return os.path.join(BASE_CGROUPS, hierarchy, AGENT_NAME, cgroup_name).rstrip(os.path.sep)

    @staticmethod
    def _construct_systemd_path_for_hierarchy(hierarchy, cgroup_name):
        return os.path.join(BASE_CGROUPS, hierarchy, 'system.slice', cgroup_name).rstrip(os.path.sep)

    @staticmethod
    def for_extension(name):
        return CGroups(name, CGroups._construct_custom_path_for_hierarchy)

    @staticmethod
    def for_systemd_service(name):
        return CGroups(name.lower(), CGroups._construct_systemd_path_for_hierarchy)

    @staticmethod
    def enabled():
        return CGroups._osutil.is_cgroups_supported() and CGroups._enabled

    @staticmethod
    def disable():
        CGroups._enabled = False

    @staticmethod
    def enable():
        CGroups._enabled = True

    def __init__(self, name, path_maker):
        """
        Construct CGroups object. Create appropriately-named directory for each hierarchy of interest.

        :param str name: Name for the cgroup (usually the full name of the extension)
        :param path_maker: Function which constructs the root path for a given hierarchy where this cgroup lives
        """
        if name == "":
            self.name = "Agents+Extensions"
            self.is_wrapper_cgroup = True
        else:
            self.name = name
            self.is_wrapper_cgroup = False

        self.cgroups = {}

        if not self.enabled():
            return

        system_hierarchies = os.listdir(BASE_CGROUPS)
        for hierarchy in CGroups._hierarchies:
            if hierarchy not in system_hierarchies:
                self.disable()
                raise CGroupsException("Hierarchy {0} is not mounted".format(hierarchy))

            cgroup_name = "" if self.is_wrapper_cgroup else self.name
            cgroup_path = path_maker(hierarchy, cgroup_name)
            if not os.path.isdir(cgroup_path):
                logger.info("Creating cgroup directory {0}".format(cgroup_path))
                CGroups._try_mkdir(cgroup_path)
            self.cgroups[hierarchy] = cgroup_path

    @staticmethod
    def is_systemd_manager():
        """
        Determine if systemd is managing system services. Many extensions are structured as a set of services,
        including the agent itself; systemd expects those services to remain in the cgroups in which it placed them.
        If this process (presumed to be the agent) is in a cgroup that looks like one created by systemd, we can
        assume systemd is in use.

        :return: True if systemd is managing system services
        :rtype: Bool
        """
        if not CGroups.enabled():
            return False
        if CGroups._use_systemd is None:
            hierarchy = METRIC_HIERARCHIES[0]
            path = CGroups.get_my_cgroup_folder(hierarchy)
            CGroups._use_systemd = path.startswith(CGroups._construct_systemd_path_for_hierarchy(hierarchy, ""))
        return CGroups._use_systemd

    @staticmethod
    def _try_mkdir(path):
        """
        Try to create a directory, recursively. If it already exists as such, do nothing. Raise the appropriate
        exception should an error occur.

        :param path: str
        """
        if not os.path.isdir(path):
            try:
                os.makedirs(path, 0o755)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    if not os.path.isdir(path):
                        raise CGroupsException(
                            "Create directory for cgroup {0}: normal file already exists with that name".format(path)
                        )
                    else:
                        pass    # There was a race to create the directory, but it's there now, and that's fine
                elif e.errno == errno.EACCES:
                    # This is unexpected, as the agent runs as root
                    raise CGroupsException("Create directory for cgroup {0}: permission denied".format(path))
                else:
                    raise

    def add(self, pid):
        """
        Add a process to the cgroups for this agent/extension.
        """
        if not self.enabled():
            return

        if self.is_wrapper_cgroup:
            raise CGroupsException("Cannot add a process to the Agents+Extensions wrapper cgroup")

        if not self._osutil.check_pid_alive(pid):
            raise CGroupsException('PID {0} does not exist'.format(pid))
        for hierarchy, cgroup in self.cgroups.items():
            tasks_file = self._get_cgroup_file(hierarchy, 'cgroup.procs')
            fileutil.append_file(tasks_file, "{0}\n".format(pid))

    def set_limits(self):
        """
        Set per-hierarchy limits based on the cgroup name (agent or particular extension)
        """
        # TODO: set limits, simply record telemetry for now
        # cg.set_cpu_limit(50)
        # cg.set_memory_limit(500)
        pass

    @staticmethod
    def _apply_wrapper_limits(path, hierarchy):
        """
        Find wrapping limits for the hierarchy and apply them to the cgroup denoted by the path

        :param path: str
        :param hierarchy: str
        """
        pass

    @staticmethod
    def _setup_wrapper_groups():
        """
        For each hierarchy, construct the wrapper cgroup and apply the appropriate limits
        """
        for hierarchy in METRIC_HIERARCHIES:
            root_dir = CGroups._construct_custom_path_for_hierarchy(hierarchy, "")
            CGroups._try_mkdir(root_dir)
            CGroups._apply_wrapper_limits(root_dir, hierarchy)

    @staticmethod
    def setup(suppress_process_add=False):
        """
        Only needs to be called once, and should be called from the -daemon instance of the agent.
            Mount the cgroup fs if necessary
            Create wrapper cgroups for agent-plus-extensions and set limits on them;
            Add this process to the "agent" cgroup, if required
        Actual collection of metrics from cgroups happens in the -run-exthandlers instance
        """
        cgroups_enabled = True
        if CGroups.enabled():
            try:
                CGroups._osutil.mount_cgroups()
                if not suppress_process_add:
                    CGroups._setup_wrapper_groups()
                    pid = int(os.getpid())
                    if not CGroups.is_systemd_manager():
                        cg = CGroups.for_extension(AGENT_NAME)
                        cg.add(pid)
                        logger.info("Add daemon process pid {0} to {1} cgroup".format(pid, cg.name))
                    else:
                        logger.info("Daemon process pid {0} cgroup managed by systemd".format(pid))
                status = "OK"
            except CGroupsException as cge:
                status = cge.msg
                cgroups_enabled = False
                CGroups.disable()
        else:
            status = "Cgroups not supported by platform"

        from azurelinuxagent.common.event import add_event, WALAEventOperation
        add_event(
            AGENT_NAME,
            version=CURRENT_VERSION,
            op=WALAEventOperation.InitializeCGroups,
            is_success=cgroups_enabled,
            message=status,
            log_event=False)

    @staticmethod
    def add_to_extension_cgroup(name, pid=int(os.getpid())):
        """
        Create cgroup directories for this extension in each of the hierarchies and add this process to the new cgroup.
        Should only be called when creating sub-processes and invoked inside the fork/exec window. As a result,
        there's no point in returning the CGroups object itself; the goal is to move the child process into the
        cgroup before the new code even starts running.

        :param str name: Short name of extension, suitable for naming directories in the filesystem
        :param int pid: Process id of extension to be added to the cgroup
        """
        if not CGroups.enabled():
            return
        if name == AGENT_NAME:
            logger.warn('Extension cgroup name cannot match agent cgroup name ({0})'.format(AGENT_NAME))
            return

        try:
            logger.info("Move process {0} into cgroups for extension {1}".format(pid, name))
            CGroups.for_extension(name).add(pid)
        except Exception as ex:
            logger.warn("Unable to move process {0} into cgroups for extension {1}: {2}".format(pid, name, ex))

    @staticmethod
    def get_my_cgroup_path(hierarchy_id):
        """
        Get the cgroup path "suffix" for this process for the given hierarchy ID. The leading "/" is always stripped,
        so the suffix is suitable for passing to os.path.join(). (If the process is in the root cgroup, an empty
        string is returned, and os.path.join() will still do the right thing.)

        :param hierarchy_id: str
        :return: str
        """
        cgroup_paths = fileutil.read_file("/proc/self/cgroup")
        for entry in cgroup_paths.splitlines():
            fields = entry.split(':')
            if fields[0] == hierarchy_id:
                return fields[2].lstrip(os.path.sep)
        raise CGroupsException("This process belongs to no cgroup for hierarchy ID {0}".format(hierarchy_id))

    @staticmethod
    def get_hierarchy_id(hierarchy):
        """
        Get the cgroups hierarchy ID for a given hierarchy name

        :param hierarchy:
        :return: str
        """
        cgroup_states = fileutil.read_file("/proc/cgroups")
        for entry in cgroup_states.splitlines():
            fields = entry.split('\t')
            if fields[0] == hierarchy:
                return fields[1]
        raise CGroupsException("Cgroup hierarchy {0} not found in /proc/cgroups".format(hierarchy))

    @staticmethod
    def get_my_cgroup_folder(hierarchy):
        """
        Find the path of the cgroup in which this process currently lives for the given hierarchy.

        :param hierarchy: str
        :return: str
        """
        hierarchy_id = CGroups.get_hierarchy_id(hierarchy)
        return os.path.join(BASE_CGROUPS, hierarchy, CGroups.get_my_cgroup_path(hierarchy_id))

    def _get_cgroup_file(self, hierarchy, file_name):
        return os.path.join(self.cgroups[hierarchy], file_name)

    @staticmethod
    def _convert_cpu_limit_to_fraction(value):
        """
        Convert a CPU limit from percent (e.g. 50 meaning 50%) to a decimal fraction (0.50).
        :return: Fraction of one CPU to be made available (e.g. 0.5 means half a core)
        :rtype: float
        """
        try:
            limit = float(value)
        except ValueError:
            raise CGroupsException('CPU Limit must be convertible to a float')

        if limit <= float(0) or limit > float(CGroups.get_num_cores() * 100):
            raise CGroupsException('CPU Limit must be between 0 and 100 * numCores')

        return limit / 100.0

    def get_file_contents(self, hierarchy, file_name):
        """
        Retrieve the value of a parameter from a hierarchy.

        :param str hierarchy: Name of cgroup metric hierarchy
        :param str file_name: Name of file within that metric hierarchy
        :return: Entire contents of the file
        :rtype: str
        """
        if hierarchy in self.cgroups:
            parameter_file = self._get_cgroup_file(hierarchy, file_name)
            try:
                return fileutil.read_file(parameter_file)
            except Exception:
                raise CGroupsException("Could not retrieve cgroup file {0}/{1}".format(hierarchy, file_name))
        else:
            raise CGroupsException("{0} subsystem not available in cgroup {1}. cgroup paths: {2}".format(
                hierarchy, self.name, self.cgroups))

    def get_parameter(self, hierarchy, parameter_name):
        """
        Retrieve the value of a parameter from a hierarchy.
        Assumes the parameter is the sole line of the file.

        :param str hierarchy: Name of cgroup metric hierarchy
        :param str parameter_name: Name of file within that metric hierarchy
        :return: The first line of the file, without line terminator
        :rtype: str
        """
        result = ""
        try:
            values = self.get_file_contents(hierarchy, parameter_name).splitlines()
            result = values[0]
        except IndexError:
            parameter_filename = self._get_cgroup_file(hierarchy, parameter_name)
            logger.periodic(logger.EVERY_DAY, "File {0} is empty but should not be".format(parameter_filename))
        except CGroupsException as e:
            logger.periodic(logger.EVERY_DAY, "{0}".format(e))
        except Exception as e:
            parameter_filename = self._get_cgroup_file(hierarchy, parameter_name)
            logger.periodic(logger.EVERY_DAY, "Exception while attempting to read {0}: {1}".format(
                parameter_filename, e))
        return result

    def set_cpu_limit(self, limit=None):
        """
        Limit this cgroup to a percentage of a single core. limit=10 means 10% of one core; 150 means 150%, which
        is useful only in multi-core systems.
        To limit a cgroup to utilize 10% of a single CPU, use the following commands:
            # echo 10000 > /cgroup/cpu/red/cpu.cfs_quota_us
            # echo 100000 > /cgroup/cpu/red/cpu.cfs_period_us

        :param limit:
        """
        if not CGroups.enabled():
            return

        if limit is None:
            return

        if 'cpu' in self.cgroups:
            total_units = float(self.get_parameter('cpu', 'cpu.cfs_period_us'))
            limit_units = self._convert_cpu_limit_to_fraction(limit) * total_units
            cpu_shares_file = self._get_cgroup_file('cpu', 'cpu.cfs_quota_us')
            fileutil.write_file(cpu_shares_file, "{0}\n".format(limit_units))
        else:
            raise CGroupsException("CPU hierarchy not available in this cgroup")

    @staticmethod
    def get_num_cores():
        """
        Return the number of CPU cores exposed to this system.

        :return: int
        """
        return CGroups._osutil.get_processor_cores()

    @staticmethod
    def _format_memory_value(unit, limit=None):
        units = {'bytes': 1, 'kilobytes': 1024, 'megabytes': 1024*1024, 'gigabytes': 1024*1024*1024}
        if unit not in units:
            raise CGroupsException("Unit must be one of {0}".format(units.keys()))
        if limit is None:
            value = MEMORY_DEFAULT
        else:
            try:
                limit = float(limit)
            except ValueError:
                raise CGroupsException('Limit must be convertible to a float')
            else:
                value = int(limit * units[unit])
        return value

    def set_memory_limit(self, limit=None, unit='megabytes'):
        if 'memory' in self.cgroups:
            value = self._format_memory_value(unit, limit)
            memory_limit_file = self._get_cgroup_file('memory', 'memory.limit_in_bytes')
            with open(memory_limit_file, 'w+') as f:
                f.write("{0}\n".format(value))
        else:
            raise CGroupsException("Memory hierarchy not available in this cgroup")
