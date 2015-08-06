# Copyright 2014 Microsoft Corporation
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
# Requires Python 2.4+ and Openssl 1.0+
#
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx

import tests.env
import tests.tools as tools
import uuid
import unittest
import os
import json
import azurelinuxagent.protocol.v1 as v1

ext_conf_sample=u"""\
<Extensions version="1.0.0.0" goalStateIncarnation="9"><GuestAgentExtension xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
  <GAFamilies>
    <GAFamily>
      <Name>Win8</Name>
      <Uris>
        <Uri>http://rdfepirv2hknprdstr03.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr04.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr05.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr06.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr07.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr08.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr09.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr10.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr11.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr12.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
        <Uri>http://zrdfepirv2hk2prdstr01.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win8_asiaeast_manifest.xml</Uri>
      </Uris>
    </GAFamily>
    <GAFamily>
      <Name>Win7</Name>
      <Uris>
        <Uri>http://rdfepirv2hknprdstr03.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr04.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr05.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr06.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr07.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr08.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr09.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr10.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr11.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
        <Uri>http://rdfepirv2hknprdstr12.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
        <Uri>http://zrdfepirv2hk2prdstr01.blob.core.windows.net/bfd5c281a7dc4e4b84381eb0b47e3aaf/Microsoft.WindowsAzure.GuestAgent_Win7_asiaeast_manifest.xml</Uri>
      </Uris>
    </GAFamily>
  </GAFamilies>
</GuestAgentExtension>
<Plugins>
  <Plugin name="OSTCExtensions.ExampleHandlerLinux" version="1.4" location="http://rdfepirv2hknprdstr03.blob.core.windows.net/b01058962be54ceca550a390fa5ff064/Microsoft.OSTCExtensions_CustomScriptForLinuxTest_asiaeast_manifest.xml" config="" state="enabled" autoUpgrade="true" failoverlocation="http://rdfepirv2hknprdstr04.blob.core.windows.net/b01058962be54ceca550a390fa5ff064/Microsoft.OSTCExtensions_CustomScriptForLinuxTest_asiaeast_manifest.xml" runAsStartupTask="false" isJson="true" />
</Plugins>
<PluginSettings>
  <Plugin name="OSTCExtensions.ExampleHandlerLinux" version="1.4">
    <RuntimeSettings seqNo="6">{"runtimeSettings":[{"handlerSettings":{"protectedSettingsCertThumbprint":"4037FBF5F1F3014F99B5D6C7799E9B20E6871CB3","protectedSettings":"MIICWgYJK","publicSettings":{"foo":"bar"}}}]}</RuntimeSettings>
  </Plugin>
</PluginSettings>
<StatusUploadBlob>https://yuezhatest.blob.core.windows.net/vhds/test-cs12.test-cs12.test-cs12.status?sr=b&amp;sp=rw&amp;se=9999-01-01&amp;sk=key1&amp;sv=2014-02-14&amp;sig=hfRh7gzUE7sUtYwke78IOlZOrTRCYvkec4hGZ9zZzXo%3D</StatusUploadBlob></Extensions>
"""

manifest_sample=u"""\
<?xml version="1.0" encoding="utf-8"?>
<PluginVersionManifest xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
    <Plugins>
        <Plugin>
            <Version>1.0</Version>
            <Uris>
                <Uri>http://blahblah</Uri>
            </Uris>
        </Plugin>
        <Plugin>
            <Version>1.1</Version>
            <Uris>
                <Uri>http://blahblah</Uri>
            </Uris>
        </Plugin>
    </Plugins>
    <InternalPlugins>
        <Plugin>
            <Version>1.2</Version>
            <Uris>
                <Uri>http://blahblah</Uri>
            </Uris>
    </Plugin>
</InternalPlugins>
</PluginVersionManifest>
"""

EmptySettings=u"""\
<Extensions>
    <Plugins>
        <Plugin name="OSTCExtensions.ExampleHandlerLinux" version="1.4" location="http://rdfepirv2hknprdstr03.blob.core.windows.net/b01058962be54ceca550a390fa5ff064/Microsoft.OSTCExtensions_CustomScriptForLinuxTest_asiaeast_manifest.xml" config="" state="enabled" autoUpgrade="true" failoverlocation="http://rdfepirv2hknprdstr04.blob.core.windows.net/b01058962be54ceca550a390fa5ff064/Microsoft.OSTCExtensions_CustomScriptForLinuxTest_asiaeast_manifest.xml" runAsStartupTask="false" isJson="true" />
    </Plugins>
  <StatusUploadBlob>https://yuezhatest.blob.core.windows.net/vhds/test-cs12.test-cs12.test-cs12.status?sr=b&amp;sp=rw&amp;se=9999-01-01&amp;sk=key1&amp;sv=2014-02-14&amp;sig=hfRh7gzUE7sUtYwke78IOlZOrTRCYvkec4hGZ9zZzXo%3D</StatusUploadBlob>
</Extensions>
"""

EmptyPublicSettings=u"""\
<Extensions>
    <Plugins>
        <Plugin name="OSTCExtensions.ExampleHandlerLinux" version="1.4" location="http://rdfepirv2hknprdstr03.blob.core.windows.net/b01058962be54ceca550a390fa5ff064/Microsoft.OSTCExtensions_CustomScriptForLinuxTest_asiaeast_manifest.xml" config="" state="enabled" autoUpgrade="true" failoverlocation="http://rdfepirv2hknprdstr04.blob.core.windows.net/b01058962be54ceca550a390fa5ff064/Microsoft.OSTCExtensions_CustomScriptForLinuxTest_asiaeast_manifest.xml" runAsStartupTask="false" isJson="true" />
    </Plugins>
  <PluginSettings>
      <Plugin name="OSTCExtensions.ExampleHandlerLinux" version="1.4">
        <RuntimeSettings seqNo="6">{"runtimeSettings":[{"handlerSettings":{"protectedSettingsCertThumbprint":"4037FBF5F1F3014F99B5D6C7799E9B20E6871CB3","protectedSettings":"MIICWgYJK"}}]}</RuntimeSettings>
      </Plugin>
  </PluginSettings>
  <StatusUploadBlob>https://yuezhatest.blob.core.windows.net/vhds/test-cs12.test-cs12.test-cs12.status?sr=b&amp;sp=rw&amp;se=9999-01-01&amp;sk=key1&amp;sv=2014-02-14&amp;sig=hfRh7gzUE7sUtYwke78IOlZOrTRCYvkec4hGZ9zZzXo%3D</StatusUploadBlob>
</Extensions>
"""

class TestExtensionsConfig(unittest.TestCase):
    def test_extensions_config(self):
        config = v1.ExtensionsConfig(ext_conf_sample)
        extensions = config.ext_handlers.extHandlers
        self.assertNotEquals(None, extensions)
        self.assertEquals(1, len(extensions))
        self.assertNotEquals(None, extensions[0])
        extension = extensions[0]
        self.assertEquals("OSTCExtensions.ExampleHandlerLinux", 
                          extension.name)
        self.assertEquals("1.4", extension.properties.version)
        self.assertEquals('auto', extension.properties.upgradePolicy)
        self.assertEquals("enabled", extension.properties.state)
        settings = extension.properties.extensions[0]
        self.assertEquals("4037FBF5F1F3014F99B5D6C7799E9B20E6871CB3", 
                          settings.certificateThumbprint)
        self.assertEquals("MIICWgYJK", settings.privateSettings)
        self.assertEquals(json.loads('{"foo":"bar"}'), 
                          settings.publicSettings)

        man = v1.ExtensionManifest(manifest_sample)
        self.assertNotEquals(None, man.pkg_list)
        self.assertEquals(3, len(man.pkg_list.versions))
    
    def test_empty_settings(self):
        config = v1.ExtensionsConfig(EmptySettings)
   
    def test_empty_public_settings(self):
        config = v1.ExtensionsConfig(EmptyPublicSettings)
   
if __name__ == '__main__':
    unittest.main()
