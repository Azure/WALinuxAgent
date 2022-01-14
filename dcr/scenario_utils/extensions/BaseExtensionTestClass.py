import time
from typing import List

from azure.core.polling import LROPoller

from dcr.scenario_utils.azure_models import ComputeManager
from dcr.scenario_utils.logging_utils import LoggingHandler
from dcr.scenario_utils.models import ExtensionMetaData, get_vm_data_from_env


class BaseExtensionTestClass(LoggingHandler):

    def __init__(self, extension_data: ExtensionMetaData):
        super().__init__()
        self.__extension_data = extension_data
        self.__vm_data = get_vm_data_from_env()
        self.__compute_manager = ComputeManager().compute_manager

    def get_ext_props(self, settings=None, protected_settings=None, auto_upgrade_minor_version=True,
                      force_update_tag=None):

        return self.__compute_manager.get_ext_props(
            extension_data=self.__extension_data,
            settings=settings,
            protected_settings=protected_settings,
            auto_upgrade_minor_version=auto_upgrade_minor_version,
            force_update_tag=force_update_tag
        )

    def run(self, ext_props: List, remove: bool = True, continue_on_error: bool = False):

        def __add_extension():
            extension: LROPoller = self.__compute_manager.extension_func.begin_create_or_update(
                self.__vm_data.rg_name,
                self.__vm_data.name,
                self.__extension_data.name,
                ext_prop
            )
            self.log.info("Add extension: {0}".format(extension.result(timeout=5 * 60)))

        def __remove_extension():
            self.__compute_manager.extension_func.begin_delete(
                self.__vm_data.rg_name,
                self.__vm_data.name,
                self.__extension_data.name
            ).result()
            self.log.info(f"Delete vm extension {self.__extension_data.name} successful")

        def _retry_on_retryable_error(func):
            retry = 1
            while retry < 5:
                try:
                    func()
                    break
                except Exception as err_:
                    if "RetryableError" in str(err_) and retry < 5:
                        self.log.warning(f"({retry}/5) Ran into RetryableError, retrying in 30 secs: {err_}")
                        time.sleep(30)
                        retry += 1
                        continue
                    raise

        try:
            for ext_prop in ext_props:
                try:
                    _retry_on_retryable_error(__add_extension)
                    # Validate success from instance view
                    _retry_on_retryable_error(self.validate_ext)
                except Exception as err:
                    if continue_on_error:
                        self.log.exception("Ran into error but ignoring it as asked: {0}".format(err))
                        continue
                    else:
                        raise
        finally:
            # Always try to delete extensions if asked to remove even on errors
            if remove:
                _retry_on_retryable_error(__remove_extension)

    def validate_ext(self):
        """
        Validate if the extension operation was successful from the Instance View
        :raises: Exception if either unable to fetch instance view or if extension not successful
        """
        retry = 0
        max_retry = 3
        ext_instance_view = None
        status = None

        while retry < max_retry:
            try:
                ext_instance_view = self.__compute_manager.get_extension_instance_view(self.__extension_data.name)
                if ext_instance_view is None:
                    raise Exception("Extension not found")
                elif not ext_instance_view.instance_view:
                    raise Exception("Instance view not present")
                elif not ext_instance_view.instance_view.statuses or len(ext_instance_view.instance_view.statuses) < 1:
                    raise Exception("Instance view status not present")
                else:
                    status = ext_instance_view.instance_view.statuses[0].code
                    status_message = ext_instance_view.instance_view.statuses[0].message
                    self.log.info('Extension Status: \n\tCode: [{0}]\n\tMessage: {1}'.format(status, status_message))
                    break
            except Exception as err:
                self.log.exception(f"Ran into error: {err}")
                retry += 1
                if retry < max_retry:
                    self.log.info("Retrying in 30 secs")
                    time.sleep(30)
                raise

        if 'succeeded' not in status:
            raise Exception(f"Extension did not succeed. Last Instance view: {ext_instance_view}")
