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
from ..plugin import Plugin
from safeguard.sessions.plugin import AAResponse
from mock import patch
from textwrap import dedent

CONFIG = """
[plugin]
"""


def test_authentication_is_not_performed():
    assert Plugin(configuration=CONFIG).do_authenticate() is None


def test_target_ip_is_resolved():
    with patch('safeguard.sessions.plugin.host_resolver.HostResolver.resolve_hosts_by_ip') as mock_resolver:
        target_server = '1.2.3.4'
        Plugin(configuration=CONFIG).authorize({},{},target_server=target_server, target_username="test_user")
        mock_resolver.assert_called_once_with(target_server)


def test_target_ip_resolved_to_one_host_in_whitelist_is_accepted():
    _assert_for_verdict(
        target_ip='DONTCARE',
        target_ip_resolved=['host1234'],
        whitelist_in_config=['host1234'],
        expected_verdict='ACCEPT'
    )


def _assert_for_verdict(target_ip, target_ip_resolved, whitelist_in_config, expected_verdict='ACCEPT'):
    testconfig = dedent("""
        [plugin]
        [hosts_for_groups]
        __all__ = {whitelist}
    """.format(whitelist="\n         ".join(whitelist_in_config)))

    with patch('safeguard.sessions.plugin.host_resolver.HostResolver.resolve_hosts_by_ip') as mock_resolver:
        mock_resolver.return_value = target_ip_resolved
        result = Plugin(configuration=testconfig).authorize({},{},target_server=target_ip, target_username='test_user')
        assert result['verdict'] == expected_verdict

def test_target_ip_resolved_to_one_host_not_in_whitelist_is_denied():
    _assert_for_verdict(
        target_ip='DONTCARE',
        target_ip_resolved=['different_host'],
        whitelist_in_config=['host1234'],
        expected_verdict='DENY'
    )


def test_target_ip_resolved_to_multiple_hosts_in_whitelist_is_accepted():
    _assert_for_verdict(
        target_ip='DONTCARE',
        target_ip_resolved=['host1234', 'different_host'],
        whitelist_in_config=['host1234'],
        expected_verdict='ACCEPT'
    )


def test_target_ip_resolved_to_one_hosts_in_multiline_whitelist_is_accepted():
    _assert_for_verdict(
        target_ip='DONTCARE',
        target_ip_resolved=['host1234'],
        whitelist_in_config=['host4567', 'foo', 'host1234', 'bar'],
        expected_verdict='ACCEPT'
    )


def test_target_ip_resolved_to_multiple_hosts_in_multiline_whitelist_is_accepted():
    _assert_for_verdict(
        target_ip='DONTCARE',
        target_ip_resolved=['badhost1', 'host1234', 'badhost2'],
        whitelist_in_config=['host4567', 'foo', 'host1234', 'bar'],
        expected_verdict='ACCEPT'
    )


def test_space_comma_and_newline_delimiters_all_work_in_whitelist():
    testconfig = dedent("""
        [plugin]
        [hosts_for_groups]
        __all__ = host0, host1 host2
                  host3
    """)

    with patch('safeguard.sessions.plugin.host_resolver.HostResolver.resolve_hosts_by_ip') as mock_resolver:
        for i in range(4):
            mock_resolver.return_value = ['host' + str(i)]
            result = Plugin(configuration=testconfig).authorize({},{},target_server='DONTCARE', target_username='test_user')
            assert result['verdict'] == 'ACCEPT'


def test_matching_falls_back_to_ip_match_if_resolving_failed():
    _assert_for_verdict(
        target_ip='1.2.3.4',
        target_ip_resolved=[],
        whitelist_in_config=['host4567', 'foo', 'host1234', '1.2.3.4'],
        expected_verdict='ACCEPT'
    )


def test_session_accepted_if_match_found_for_gateway_group():
    testconfig = dedent("""
        [plugin]
        [hosts_for_groups]
        test_group = host1234, other_host, foo, bar
    """)

    with patch('safeguard.sessions.plugin.host_resolver.HostResolver.resolve_hosts_by_ip') as mock_resolver:
        mock_resolver.return_value = ['host1234']
        result = Plugin(configuration=testconfig).authorize({},{},
                    target_server='DONTCARE',
                    gateway_groups=['fake_group', 'foo', 'bar', 'test_group'],
                    target_username='test_user'
                )
        assert result['verdict'] == 'ACCEPT'


def test_wildcards_can_be_used_in_host_lists_for_single_resolved_hostname():
    _assert_for_verdict(
        target_ip='DONTCARE',
        target_ip_resolved=['host1234'],
        whitelist_in_config=['h?st*'],
        expected_verdict='ACCEPT'
    )


def test_wildcards_can_be_used_in_host_lists_for_multiple_resolved_hostname():
    _assert_for_verdict(
        target_ip='DONTCARE',
        target_ip_resolved=['host1234', 'foobar'],
        whitelist_in_config=['*bar'],
        expected_verdict='ACCEPT'
    )


def test_groups_for_host_specification_works_for_single_group():
    testconfig = dedent("""
        [plugin]
        [groups_for_hosts]
        host1234 = test_group
    """)
    with patch('safeguard.sessions.plugin.host_resolver.HostResolver.resolve_hosts_by_ip') as mock_resolver:
        mock_resolver.return_value = ['host1234']
        result = Plugin(configuration=testconfig).authorize({},{},
                    target_server='DONTCARE',
                    gateway_groups=['fake_group', 'test_group'],
                    target_username='test_user'
                )
        assert result['verdict'] == 'ACCEPT'


def test_groups_for_host_specification_supports_wildcards_for_hosts():
    testconfig = dedent("""
        [plugin]
        [groups_for_hosts]
        host* = test_group
    """)
    with patch('safeguard.sessions.plugin.host_resolver.HostResolver.resolve_hosts_by_ip') as mock_resolver:
        mock_resolver.return_value = ['host1234']
        result = Plugin(configuration=testconfig).authorize({},{},
                    target_server='DONTCARE',
                    gateway_groups=['fake_group', 'test_group'],
                    target_username='test_user'
                )
        assert result['verdict'] == 'ACCEPT'
