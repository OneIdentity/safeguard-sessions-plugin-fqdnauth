#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from safeguard.sessions.plugin import AAPlugin, AAResponse
from safeguard.sessions.plugin import HostResolver
import re
from fnmatch import fnmatch


class Plugin(AAPlugin):
    def __init__(self, configuration):
        super().__init__(configuration)

    def do_authenticate(self):
        return None

    def do_authorize(self):
        target_hosts = self._resolve_ip(self.connection.target_server)

        if self._hosts_for_groups_match(target_hosts, self.connection.gateway_groups)\
                or self._groups_for_hosts_match(target_hosts, self.connection.gateway_groups):
            return AAResponse.accept()
        else:
            return AAResponse.deny()

    @staticmethod
    def _resolve_ip(ip):
        hosts = HostResolver().resolve_hosts_by_ip(ip)
        if len(hosts) == 0:
            hosts = [ip]
        return hosts

    def _hosts_for_groups_match(self, hosts, groups):
        if not self.plugin_configuration.get_options('hosts_for_groups'):
            return False

        group_list = ['__all__'] + groups if groups is not None else ['__all__']

        for group in group_list:
            if self._hosts_allowed_for_group(hosts, group):
                return True
        return False

    def _hosts_allowed_for_group(self, hosts, group):
        whitelist_for_group = self.plugin_configuration.get('hosts_for_groups', group)
        if whitelist_for_group is None:
            return False
        return self._hosts_have_match_in_list(hosts, self._split_entry(whitelist_for_group))

    @staticmethod
    def _split_entry(entry):
        return re.split('[, \\n]', entry)

    @staticmethod
    def _hosts_have_match_in_list(hosts, pattern_list):
        for host in hosts:
            for pattern in pattern_list:
                if fnmatch(host, pattern):
                    return True
        return False

    def _groups_for_hosts_match(self, hosts, groups):
        host_entries = self.plugin_configuration.get_options('groups_for_hosts')
        
        if len(host_entries) == 0 or groups is None :
            return False

        for host in hosts:
            groups_for_host = self._get_groups_for_host(host)
            if self._lists_intersect(groups, groups_for_host):
                return True
        return False

    def _get_groups_for_host(self, host):
        host_entries = self.plugin_configuration.get_options('groups_for_hosts')
        for host_entry in host_entries:
            if fnmatch(host, host_entry):
                return self._split_entry(self.plugin_configuration.get('groups_for_hosts', host_entry))
        return []

    @staticmethod
    def _lists_intersect(a, b):
        # see https://stackoverflow.com/questions/3170055/test-if-lists-share-any-items-in-python
        return not set(a).isdisjoint(b)

