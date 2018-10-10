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

from __future__ import absolute_import
from __future__ import print_function

import mock

import reactive.octavia_handlers as handlers

import charms_openstack.test_utils as test_utils


class TestRegisteredHooks(test_utils.TestRegisteredHooks):

    def test_hooks(self):
        defaults = [
            'charm.installed',
            'amqp.connected',
            'shared-db.connected',
            'identity-service.connected',
            'identity-service.available',
            'config.changed',
            'update-status']
        hook_set = {
            'when': {
                'render': ('shared-db.available',
                           'identity-service.available',
                           'amqp.available',),
                'init_db': ('config.rendered',),
                'cluster_connected': ('ha.connected',),
            },
            'when_not': {
                'init_db': ('db.synced',),
                'cluster_connected': ('ha.available',),
            },
        }
        # test that the hooks were registered via the
        # reactive.octavia_handlers
        self.registered_hooks_test_helper(handlers, hook_set, defaults)


class TestRender(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.octavia_charm = mock.MagicMock()
        self.patch_object(handlers.charm, 'provide_charm_instance',
                          new=mock.MagicMock())
        self.provide_charm_instance().__enter__.return_value = \
            self.octavia_charm
        self.provide_charm_instance().__exit__.return_value = None

    def test_render(self):
        self.patch('charms.reactive.set_state', 'set_state')
        handlers.render('arg1', 'arg2')
        self.octavia_charm.render_with_interfaces.assert_called_once_with(
            ('arg1', 'arg2'))
        self.octavia_charm.assess_status.assert_called_once_with()
        self.set_state.assert_called_once_with('config.rendered')

    def test_init_db(self):
        self.patch('charms.reactive.set_state', 'set_state')
        handlers.init_db()
        self.octavia_charm.db_sync.assert_called_once_with()
        self.octavia_charm.restart_all.assert_called_once_with()
        self.set_state.assert_called_once_with('db.synced')
        self.octavia_charm.assess_status.assert_called_once_with()

    def test_cluster_connected(self):
        hacluster = mock.MagicMock()
        handlers.cluster_connected(hacluster)
        self.octavia_charm.configure_ha_resources.assert_called_once_with(
            hacluster)
        self.octavia_charm.assess_status.assert_called_once_with()
