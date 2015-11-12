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
from  .tools import *
import uuid
import unittest
import os
import json
import azurelinuxagent.utils.fileutil as fileutil
import azurelinuxagent.protocol.v1 as v1

certs_sample=u"""\
<?xml version="1.0" encoding="utf-8"?>
<CertificateFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="certificates10.xsd">
  <Version>2012-11-30</Version>
  <Incarnation>12</Incarnation>
  <Format>Pkcs7BlobWithPfxContents</Format>
  <Data>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
h+249Wj0Bw==
</Data>
</CertificateFile>
"""

transport_cert=u"""\
-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJANujJuVt5eC8MA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNV
BAMMDkxpbnV4VHJhbnNwb3J0MCAXDTE0MTAyNDA3MjgwN1oYDzIxMDQwNzEyMDcy
ODA3WjAZMRcwFQYDVQQDDA5MaW51eFRyYW5zcG9ydDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBANPcJAkd6V5NeogSKjIeTXOWC5xzKTyuJPt4YZMVSosU
0lI6a0wHp+g2fP22zrVswW+QJz6AVWojIEqLQup3WyCXZTv8RUblHnIjkvX/+J/G
aLmz0G5JzZIpELL2C8IfQLH2IiPlK9LOQH00W74WFcK3QqcJ6Kw8GcVaeSXT1r7X
QcGMqEjcWJkpKLoMJv3LMufE+JMdbXDUGY+Ps7Zicu8KXvBPaKVsc6H2jrqBS8et
jXbzLyrezTUDz45rmyRJzCO5Sk2pohuYg73wUykAUPVxd7L8WnSyqz1v4zrObqnw
BAyor67JR/hjTBfjFOvd8qFGonfiv2Vnz9XsYFTZsXECAwEAAaNQME4wHQYDVR0O
BBYEFL8i/sehpGV6IEDX7F0WQHQ/ZXOyMB8GA1UdIwQYMBaAFL8i/sehpGV6IEDX
7F0WQHQ/ZXOyMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAMPLrimT
Gptu5pLRHPT8OFRN+skNSkepYaUaJuq6cSKxLumSYkD8++rohu+1+a7t1YNjjNSJ
8ohRAynRJ7aRqwBmyX2OPLRpOfyRZwR0rcFfAMORm/jOE6WBdqgYD2L2b+tZplGt
/QqgQzebaekXh/032FK4c74Zg5r3R3tfNSUMG6nLauWzYHbQ5SCdkuQwV0ehGqh5
VF1AOdmz4CC2237BNznDFQhkeU0LrqqAoE/hv5ih7klJKZdS88rOYEnVJsFFJb0g
qaycXjOm5Khgl4hKrd+DBD/qj4IVVzsmdpFli72k6WLBHGOXusUGo/3isci2iAIt
DsfY6XGSEIhZnA4=
-----END CERTIFICATE-----
"""

transport_private=u"""\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDT3CQJHeleTXqI
EioyHk1zlguccyk8riT7eGGTFUqLFNJSOmtMB6foNnz9ts61bMFvkCc+gFVqIyBK
i0Lqd1sgl2U7/EVG5R5yI5L1//ifxmi5s9BuSc2SKRCy9gvCH0Cx9iIj5SvSzkB9
NFu+FhXCt0KnCeisPBnFWnkl09a+10HBjKhI3FiZKSi6DCb9yzLnxPiTHW1w1BmP
j7O2YnLvCl7wT2ilbHOh9o66gUvHrY128y8q3s01A8+Oa5skScwjuUpNqaIbmIO9
8FMpAFD1cXey/Fp0sqs9b+M6zm6p8AQMqK+uyUf4Y0wX4xTr3fKhRqJ34r9lZ8/V
7GBU2bFxAgMBAAECggEBAM4hsfog3VAAyIieS+npq+gbhH6bWfMNaTQ3g5CNNbMu
9hhFeOJHzKnWYjSlamgBQhAfTN+2E+Up+iAtcVUZ/lMumrQLlwgMo1vgmvu5Kxmh
/YE5oEG+k0JzrCjD1trwd4zvc3ZDYyk/vmVTzTOc311N248UyArUiyqHBbq1a4rP
tJhCLn2c4S7flXGF0MDVGZyV9V7J8N8leq/dRGMB027Li21T+B4mPHXa6b8tpRPL
4vc8sHoUJDa2/+mFDJ2XbZfmlgd3MmIPlRn1VWoW7mxgT/AObsPl7LuQx7+t80Wx
hIMjuKUHRACQSLwHxJ3SQRFWp4xbztnXSRXYuHTscLUCgYEA//Uu0qIm/FgC45yG
nXtoax4+7UXhxrsWDEkbtL6RQ0TSTiwaaI6RSQcjrKDVSo/xo4ZySTYcRgp5GKlI
CrWyNM+UnIzTNbZOtvSIAfjxYxMsq1vwpTlOB5/g+cMukeGg39yUlrjVNoFpv4i6
9t4yYuEaF4Vww0FDd2nNKhhW648CgYEA0+UYH6TKu03zDXqFpwf4DP2VoSo8OgfQ
eN93lpFNyjrfzvxDZkGF+7M/ebyYuI6hFplVMu6BpgpFP7UVJpW0Hn/sXkTq7F1Q
rTJTtkTp2+uxQVP/PzSOqK0Twi5ifkfoEOkPkNNtTiXzwCW6Qmmcvln2u893pyR5
gqo5BHR7Ev8CgYAb7bXpN9ZHLJdMHLU3k9Kl9YvqOfjTxXA3cPa79xtEmsrTys4q
4HuL22KSII6Fb0VvkWkBAg19uwDRpw78VC0YxBm0J02Yi8b1AaOhi3dTVzFFlWeh
r6oK/PAAcMKxGkyCgMAZ3hstsltGkfXMoBwhW+yL6nyOYZ2p9vpzAGrjkwKBgQDF
0huzbyXVt/AxpTEhv07U0enfjI6tnp4COp5q8zyskEph8yD5VjK/yZh5DpmFs6Kw
dnYUFpbzbKM51tToMNr3nnYNjEnGYVfwWgvNHok1x9S0KLcjSu3ki7DmmGdbfcYq
A2uEyd5CFyx5Nr+tQOwUyeiPbiFG6caHNmQExLoiAQKBgFPy9H8///xsadYmZ18k
r77R2CvU7ArxlLfp9dr19aGYKvHvnpsY6EuChkWfy8Xjqn3ogzgrHz/rn3mlGUpK
vbtwtsknAHtTbotXJwfaBZv2RGgGRr3DzNo6ll2Aez0lNblZFXq132h7+y5iLvar
4euORaD/fuM4UPlR5mN+bypU
-----END PRIVATE KEY-----
"""

def MockGetOpensslCmd():
    return 'openssl'

class TestCertificates(unittest.TestCase):
    
    def test_certificates(self):
        crt1 = '/tmp/33B0ABCE4673538650971C10F7D7397E71561F35.crt'
        crt2 = '/tmp/4037FBF5F1F3014F99B5D6C7799E9B20E6871CB3.crt'
        prv2 = '/tmp/4037FBF5F1F3014F99B5D6C7799E9B20E6871CB3.prv'
        os.chdir('/tmp')
        if os.path.isfile(crt1):
            os.remove(crt1)
        if os.path.isfile(crt2):
            os.remove(crt2)
        if os.path.isfile(prv2):
            os.remove(prv2)
        fileutil.write_file(os.path.join('/tmp', "TransportCert.pem"), 
                            transport_cert)
        fileutil.write_file(os.path.join('/tmp', "TransportPrivate.pem"), 
                            transport_private)
        client = v1.WireClient("http://foo.bar")
        config = v1.Certificates(client, certs_sample)
        self.assertNotEquals(None, config)
        self.assertTrue(os.path.isfile(crt1))
        self.assertTrue(os.path.isfile(crt2))
        self.assertTrue(os.path.isfile(prv2))

        self.assertNotEquals(0, len(config.cert_list.certificates))
        cert = config.cert_list.certificates[0]
        self.assertNotEquals(None, cert.thumbprint)
   
if __name__ == '__main__':
    unittest.main()
