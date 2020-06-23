# Copyright 2018 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

sys.path.append('src')
sys.path.append('src/lib')

# Mock out charmhelpers so that we can test without it.
import charms_openstack.test_mocks  # noqa
charms_openstack.test_mocks.mock_charmhelpers()

from unittest import mock


class _fake_decorator(object):

    def __init__(self, *args):
        pass

    def __call__(self, f):
        return f


import charmhelpers.contrib
sys.modules['charmhelpers.contrib.charmsupport'] = \
    charmhelpers.contrib.charmsupport
sys.modules['charmhelpers.contrib.charmsupport.nrpe'] = \
    charmhelpers.contrib.charmsupport.nrpe
charms = mock.MagicMock()
sys.modules['charms'] = charms
charms.leadership = mock.MagicMock()
sys.modules['charms.leadership'] = charms.leadership
charms.reactive = mock.MagicMock()
charms.reactive.when = _fake_decorator
charms.reactive.when_all = _fake_decorator
charms.reactive.when_any = _fake_decorator
charms.reactive.when_not = _fake_decorator
charms.reactive.when_none = _fake_decorator
charms.reactive.when_not_all = _fake_decorator
charms.reactive.not_unless = _fake_decorator
charms.reactive.when_file_changed = _fake_decorator
charms.reactive.collect_metrics = _fake_decorator
charms.reactive.meter_status_changed = _fake_decorator
charms.reactive.only_once = _fake_decorator
charms.reactive.hook = _fake_decorator
charms.reactive.bus = mock.MagicMock()
charms.reactive.flags = mock.MagicMock()
charms.reactive.relations = mock.MagicMock()
sys.modules['charms.reactive'] = charms.reactive
sys.modules['charms.reactive.bus'] = charms.reactive.bus
sys.modules['charms.reactive.bus'] = charms.reactive.decorators
sys.modules['charms.reactive.flags'] = charms.reactive.flags
sys.modules['charms.reactive.relations'] = charms.reactive.relations
keystoneauth1 = mock.MagicMock()
sys.modules['keystoneauth1'] = keystoneauth1
netaddr = mock.MagicMock()
sys.modules['netaddr'] = netaddr
novaclient = mock.MagicMock()
sys.modules['novaclient'] = novaclient
neutron_lib = mock.MagicMock()
sys.modules['neutron_lib'] = neutron_lib
sys.modules['neutron_lib.constants'] = neutron_lib.constants
neutronclient = mock.MagicMock()
sys.modules['neutronclient'] = neutronclient
sys.modules['neutronclient.v2_0'] = neutronclient.v2_0
