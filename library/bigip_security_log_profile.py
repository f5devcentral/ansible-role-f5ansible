#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: bigip_security_log_profile
short_description: Manage logging profiles on a BIG-IP
description:
  - Manages logging profiles configured in the system along with basic information
    about each profile.
version_added: 2.6
options:
  name:
    description:
      - Specifies the name of the log profile.
    required: True
  description:
    description:
      - Description of the log profile.
  network_firewall:
    description:
      - Configures Network Firewall related settings of the log profile.
    suboptions:
      publisher:
        description:
          - Specifies the name of the log publisher used for Network events.
      log_matches_accept_rule:
        suboptions:
          enabled:
            description:
              - This option is used to enable or disable the logging of packets that
                match ACL rules configured with an "accept" or "accept decisively" action.
            type: bool
          rate_limit:
            description:
              - This option is used to set rate limits for the logging of packets that
                match ACL rules configured with an "accept" or "accept decisively" action.
              - This option is effective only if logging of this message type is enabled.
      log_matches_drop_rule:
        suboptions:
          enabled:
            description:
              - This option is used to enable or disable the logging of packets that
                match ACL rules configured with a drop action.
            type: bool
          rate_limit:
            description:
              - This option is used to set rate limits for the logging of packets that
                match ACL rules configured with a drop action.
              - This option is effective only if logging of this message type is enabled.
      log_matches_reject_rule:
        suboptions:
          enabled:
            description:
              - This option is used to enable or disable the logging of packets that
                match ACL rules configured with a reject action.
            type: bool
          rate_limit:
            description:
              - This option is used to set rate limits for the logging of packets that
                match ACL rules configured with a reject action.
              - This option is effective only if logging of this message type is enabled.
      log_ip_errors:
        suboptions:
          enabled:
            description:
              - This option is used to enable or disable the logging of IP error packets.
            type: bool
          rate_limit:
            description:
              - This option is used to set rate limits for the logging of IP error
                packets.
              - This option is effective only if logging of this message type is enabled.
      log_tcp_errors:
        suboptions:
          enabled:
            description:
              - This option is used to enable or disable the logging of TCP error
                packets.
            type: bool
          rate_limit:
            description:
              - This option is used to set rate limits for the logging of TCP error
                packets.
              - This option is effective only if logging of this message type is enabled.
      log_tcp_events:
        suboptions:
          enabled:
            description:
              - This option is used to enable or disable the logging of TCP events on
                the client side.
              - Only 'Established' and 'Closed' states of a TCP session are logged if this
                option is enabled.
            type: bool
          rate_limit:
            description:
              - This option is used to set rate limits for the logging of TCP events
                on client side.
              - This option is effective only if logging of this message type is enabled.
      log_translation_fields:
        description:
          - This option is used to enable or disable the logging of translated
            (i.e server side) fields in ACL match and TCP events.
          - Translated fields include (but are not limited to) source address/port,
            destination address/port, IP protocol, route domain, and VLAN.
        type: bool
      log_storage_format:
        description:
          - Specifies the type of the storage format.
          - When creating a new log profile, if this parameter is not specified,
            the default is C(none).
          - When C(field-list), specifies that the log displays only the items you
            specify in the C(fields) list with C(delimiter) as the delimiter between
            the items.
          - When C(none), the messages will be logged in the default format, which
            is C("management_ip_address","bigip_hostname","context_type",
            "context_name","src_geo","src_ip", "dest_geo","dest_ip","src_port",
            "dest_port","vlan","protocol","route_domain", "translated_src_ip",
            "translated_dest_ip","translated_src_port","translated_dest_port",
            "translated_vlan","translated_ip_protocol","translated_route_domain",
            "acl_policy_type", "acl_policy_name","acl_rule_name","action",
            "drop_reason","sa_translation_type", "sa_translation_pool","flow_id",
            "source_user","source_fqdn","dest_fqdn").
        choices:
          - field-list
          - none
      log_format_delimiter:
        description:
          - Specifies the delimiter string when using a C(type) of C(field-list).
          - When creating a new profile, if this parameter is not specified, the
            default value of C(,) (the comma character) will be used.
          - This option is valid when the C(type) is set to C(field-list). It will
            be ignored otherwise.
          - Depending on the delimiter used, it may be necessary to wrap the delimiter
            in quotes to prevent YAML errors from occurring.
          - The special character C($) should not be used, and will raise an error
            if used, as it is reserved for internal use.
          - The maximum length allowed for this parameter is C(31) characters.
      log_message_fields:
        description:
          - Specifies a set of fields to be logged.
          - This option is valid when the C(type) is set to C(field-list). It will
            be ignored otherwise.
          - The order of the list is important as the server displays the selected
            traffic items in the log sequentially according to it.
        choices:
          - acl_policy_name
          - acl_policy_type
          - acl_rule_name
          - action
          - bigip_hostname
          - context_name
          - context_type
          - date_time
          - dest_fqdn
          - dest_geo
          - dest_ip
          - dest_port
          - drop_reason
          - management_ip_address
          - protocol
          - route_domain
          - sa_translation_pool
          - sa_translation_type
          - source_fqdn
          - source_user
          - src_geo
          - src_ip
          - src_port
          - translated_dest_ip
          - translated_dest_port
          - translated_ip_protocol
          - translated_route_domain
          - translated_src_ip
          - translated_src_port
          - translated_vlan
          - vlan
  dos_protection:
    description:
      - Configures DoS related settings of the log profile.
    suboptions:
      dns_publisher:
        description:
          - Specifies the name of the log publisher used for DNS DoS events.
  ip_intelligence:
    description:
      - Configures IP Intelligence related settings of the log profile.
    suboptions:
      publisher:
        description:
          - Specifies the name of the log publisher used for IP Intelligence events.
      log_translation_fields:
        description:
          - This option is used to enable or disable the logging of translated
            (i.e server side) fields in IP Intelligence log messages.
          - Translated fields include (but are not limited to) source address/port,
            destination address/port, IP protocol, route domain, and VLAN.
        type: bool
  state:
    description:
      - When C(present), ensures that the resource exists.
      - When C(absent), ensures that the resource does not exist.
    default: present
    choices:
      - present
      - absent
  partition:
    description:
      - Device partition to manage resources on.
    default: Common
extends_documentation_fragment: f5
author:
  - Tim Rupp (@caphrim007)
'''

EXAMPLES = r'''
- name: Create a security profile stub
  bigip_security_log_profile:
    name: policy1
    password: secret
    server: lb.mydomain.com
    state: present
    user: admin
  delegate_to: localhost

- name: Create/modify multiple log profiles with similar settings
  bigip_security_log_profile:
    name: "{{ item.name }}"
    description: "{{ item.description|default(omit) }}"
    network_firewall:
       publisher: "{{ item.publisher }}"
       log_matches_accept_rule:
          enabled: yes
          rate_limit: 100
       log_matches_drop_rule:
          enabled: yes
          rate_limit: 200
       log_matches_reject_rule:
          enabled: yes
       log_ip_errors:
          enabled: yes
          rate_limit: 400
       log_tcp_errors:
          enabled: yes
       log_tcp_events:
          enabled: yes
       log_translation_fields: yes
       storage_format:
          type: field-list
          delimiter: ","
          fields: "{{ field_list_1 }}"
    dos_protection:
       dns_publisher: "{{ item.publisher }}"
    ip_intelligence:
       publisher: "{{ item.publisher }}"
       log_translation_fields: yes
'''

RETURN = r'''
param1:
  description: The new param1 value of the resource.
  returned: changed
  type: bool
  sample: true
param2:
  description: The new param2 value of the resource.
  returned: changed
  type: string
  sample: Foo is bar
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.six import iteritems
from ansible.module_utils.six.moves import map

try:
    from library.module_utils.network.f5.bigip import HAS_F5SDK
    from library.module_utils.network.f5.bigip import F5Client
    from library.module_utils.network.f5.common import F5ModuleError
    from library.module_utils.network.f5.common import AnsibleF5Parameters
    from library.module_utils.network.f5.common import cleanup_tokens
    from library.module_utils.network.f5.common import fq_name
    from library.module_utils.network.f5.common import f5_argument_spec
    try:
        from library.module_utils.network.f5.common import iControlUnexpectedHTTPError
    except ImportError:
        HAS_F5SDK = False
except ImportError:
    from ansible.module_utils.network.f5.bigip import HAS_F5SDK
    from ansible.module_utils.network.f5.bigip import F5Client
    from ansible.module_utils.network.f5.common import F5ModuleError
    from ansible.module_utils.network.f5.common import AnsibleF5Parameters
    from ansible.module_utils.network.f5.common import cleanup_tokens
    from ansible.module_utils.network.f5.common import fq_name
    from ansible.module_utils.network.f5.common import f5_argument_spec
    try:
        from ansible.module_utils.network.f5.common import iControlUnexpectedHTTPError
    except ImportError:
        HAS_F5SDK = False


class Parameters(AnsibleF5Parameters):
    api_map = {
        'networkReference': 'network_firewall',
        'ipIntelligence': 'ip_intelligence',
        'protocolDnsDosPublisher': 'dos_dns_publisher'
    }

    api_attributes = [
        'description',
        'ipIntelligence',
        'networkReference',
        'protocolDnsDosPublisher',
    ]

    returnables = [
        'description',
        'ip_intelligence',
        'dos_dns_publisher',
    ]

    updatables = [
        'description',
        'ip_intelligence',
        'network_firewall',
        'dos_dns_publisher',
    ]


class ApiParameters(Parameters):
    @property
    def network_firewall(self):
        """Get network firewall details

        There can only be a single item in this list (even though it is a collection)
        :return:
        """
        result = {}
        if self._values['network_firewall'] is None or 'items' not in self._values['network_firewall']:
            return result
        return self._values['network_firewall']['items'][0]

    @property
    def ip_intelligence(self):
        if self._values['ip_intelligence'] is None:
            return None
        return self._values['ip_intelligence']


class ModuleParameters(Parameters):
    filters = dict(
        log_matches_accept_rule='logAclMatchAccept',
        log_matches_drop_rule='logAclMatchDrop',
        log_matches_reject_rule='logAclMatchReject',
        log_ip_errors='logIpErrors',
        log_tcp_errors='logTcpErrors',
        log_tcp_events='logTcpEvents',
        log_translation_fields='logTranslationFields'
    )

    rate_limits = dict(
        log_matches_accept_rule='aclMatchAccept',
        log_matches_drop_rule='aclMatchDrop',
        log_matches_reject_rule='aclMatchReject',
        log_ip_errors='ipErrors',
        log_tcp_errors='tcpErrors',
        log_tcp_events='tcpEvents',
    )

    ip_int_filters = dict(
        log_translation_fields='logTranslationFields'
    )

    @property
    def ip_intelligence(self):
        if self._values['ip_intelligence'] is None:
            return None

        result = dict()

        self._set_ip_intelligence_publisher(result)
        for filter, name in iteritems(self.ip_int_filters):
            self._set_ip_intelligence_log_filter(result, filter, name)
        return result

    def _set_ip_intelligence_publisher(self, result):
        publisher = self._values['ip_intelligence'].get('publisher', None)
        if publisher:
            result['logPublisher'] = fq_name(self.partition, publisher)

    def _set_ip_intelligence_log_filter(self, result, filter, name):
        enabled = self._values['ip_intelligence'].get(filter, None)
        if enabled is None:
            return
        elif enabled is True:
            result[name] = 'enabled'
        elif enabled is False:
            result[name] = 'disabled'

        return result

    @property
    def dos_dns_publisher(self):
        if self._values['dos_protection'] is None:
            return None
        if self._values['dos_protection']['dns_publisher'] is None:
            return None
        return fq_name(self.partition, self._values['dos_protection']['dns_publisher'])

    @property
    def network_firewall(self):
        if self._values['network_firewall'] is None:
            return None
        result = dict()

        self._set_network_firewall_publisher(result)
        self._set_network_storage_format(result)
        for filter, name in iteritems(self.filters):
            self._set_network_filter(result, filter, name)
        return result

    def _set_network_storage_format(self, result):
        format = self._values['network_firewall'].get('log_storage_format', None)
        if not format:
            return

        result['format'] = dict()
        result['format']['type'] = format

        delim = self._values['network_firewall'].get('log_format_delimiter', None)
        if delim:
            result['format']['fieldListDelimiter'] = delim

        fields = self._values['network_firewall'].get('log_message_fields', None)
        if fields:
            fields.sort()
            result['format']['fieldList'] = fields

    def _set_network_firewall_publisher(self, result):
        publisher = self._values['network_firewall'].get('publisher', None)
        if publisher:
            result['publisher'] = fq_name(self.partition, publisher)

    def _set_network_filter(self, result, filter, name):
        if not 'filter' in result:
            result['filter'] = dict()

        filter = self._values['network_firewall'][filter]

        if isinstance(filter, bool):
            enabled = filter
            self._handle_boolean_filter(result, name, enabled)
        elif filter is None:
            pass
        else:
            enabled = filter.get('enabled', None)
            self._handle_boolean_filter(result, name, enabled)
            self._set_network_filter_rate_limit(result, filter, name)

        import q; q.q("ASDASDA")
        import q; q.q(result)
        if not result['filter']:
            del result['filter']

    def _handle_boolean_filter(self, result, name, enabled):
        if enabled is True:
            result['filter'][name] = 'enabled'
        elif enabled is False:
            result['filter'][name] = 'disabled'

    def _set_network_filter_rate_limit(self, result, filter, name):
        rate_limit = filter.get('rate_limit', None)

        if rate_limit == 'indefinite':
            if not 'rateLimit' in result:
                result['rateLimit'] = dict()
            result['rateLimit'][name] = 4294967295
        else:
            try:
                limit = int(rate_limit)
                if 0 <= limit <= 4294967295:
                    if not 'rateLimit' in result:
                        result['rateLimit'] = dict()
                    result['rateLimit'][name] = limit
                else:
                    raise F5ModuleError(
                        "'rate_limit' must be between 0 and 4294967295, or, the value 'indefinite'."
                    )
            except (TypeError, ValueError):
                pass

        return result


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            pass
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    pass


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1

    @property
    def ip_intelligence(self):
        if self.have.ip_intelligence is None and self.want.ip_intelligence is None:
            return None
        if self.want.ip_intelligence is None:
            return None
        changed = False
        result = dict()
        result.update(self.have.ip_intelligence)
        for k, v in iteritems(self.want.ip_intelligence):
            if k not in result or result[k] != v:
                changed = True
                result[k] = v
        if changed:
            return dict(ip_intelligence=result)

    @property
    def dos_dns_publisher(self):
        if self.want.dos_dns_publisher is None:
            return None
        if self.want.dos_dns_publisher != self.have.dos_dns_publisher:
            return self.want.dos_dns_publisher

    @property
    def network_firewall(self):
        result = dict()

        if self.want.network_firewall is None:
            return None
        if self.have.network_firewall is None:
            return dict(
                network_firewall=self.want.network_firewall
            )

        want = self.want.network_firewall
        have = self.have.network_firewall

        import q; q.q(want, have)
        if 'publisher' in want:
            if want['publisher'] is None:
                pass
            elif 'publisher' not in have or want['publisher'] != have['publisher']:
                result['publisher'] = want['publisher']

        if 'filter' in want:
            if 'filter' not in have:
                result['filter'] = want['filter']
            else:
                for v in self.want.filters.values():
                    want_filter = want['filter'].get(v, None)
                    if want_filter is None:
                        continue
                    if want_filter != have['filter'].get(v, None):
                        if 'filter' not in result:
                            result['filter'] = dict()
                        result['filter'][v] = want['filter'][v]

        if 'format' in want:
            if 'format' not in have:
                result['format'] = want['format']
            else:
                want_type = want['format'].get('type', None)
                have_type = want['format'].get('type', None)
                if want_type is None:
                    pass
                if want_type is None and have_type is None:
                    pass
                if want_type != have_type:
                    result['format'] = dict(
                        type=want_type
                    )

                want_delim = want['format'].get('fieldListDelimiter', None)
                have_delim = want['format'].get('fieldListDelimiter', None)
                if want_delim is None:
                    pass
                if want_delim is None and have_delim is None:
                    pass
                if want_type not in ['field-list', 'user-defined']:
                    raise F5ModuleError(
                        "The 'log_format_delimiter' may not be provided when 'log_storage_format' is 'none'."
                    )

                want_fields = want['format'].get('fieldList', None)
                have_fields = want['format'].get('fieldList', None)
                if want_fields is None:
                    pass
                if want_fields is None and have_fields is None:
                    pass
                if want_type not in ['field-list', 'user-defined']:
                    raise F5ModuleError(
                        "The 'log_message_fields' parameter must include at least one supported field."
                    )

        import q; q.q(result)
        if result:
            return dict(
                network_firewall=result
            )


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = kwargs.get('client', None)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def exec_module(self):
        changed = False
        result = dict()
        state = self.want.state

        try:
            if state == "present":
                changed = self.present()
            elif state == "absent":
                changed = self.absent()
        except iControlUnexpectedHTTPError as e:
            raise F5ModuleError(str(e))

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.client.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def exists(self):
        result = self.client.api.tm.security.log.profiles.profile.exists(
            name=self.want.name,
            partition=self.want.partition
        )
        return result

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        changed = self.update_on_device()
        return changed

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def _validate_network_firewall_storage_format(self):
        if self.want.network_firewall is None:
            result = dict()
        else:
            result = self.want.network_firewall

        if 'log_storage_format' not in result:
            result['log_storage_format'] = 'none'
        elif result['log_storage_format'] == 'none':
            pass
        elif result['log_storage_format'] == 'field-list':
            if 'log_format_delimiter' not in result:
                result['log_format_delimiter'] = ','
            if 'log_message_fields' not in result or len(result['log_message_fields']) == 0:
                raise F5ModuleError(
                    "The 'log_message_fields' parameter must include at least one supported field."
                )
        self.want.update({'network_firewall': result})

    def create(self):
        self._set_changed_options()

        self._validate_network_firewall_storage_format()

        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def create_on_device(self):
        params = self.changes.api_params()
        self.client.api.tm.security.log.profiles.profile.create(
            name=self.want.name,
            partition=self.want.partition,
            **params
        )

    def update_on_device(self):
        changed = False
        params = self.changes.api_params()
        network = params.pop('networkReference', None)
        resource = self.client.api.tm.security.log.profiles.profile.load(
            name=self.want.name,
            partition=self.want.partition
        )
        if params:
            resource.modify(**params)
            changed = True
        if network:
            exists = resource.networks.network.exists(
                name=self.want.name, partition=self.want.partition
            )
            if exists:
                resource2 = resource.networks.network.load(
                    name=self.want.name, partition=self.want.partition
                )
                resource2.modify(**network)
            else:
                resource.networks.network.create(
                    name=self.want.name, partition=self.want.partition,
                    **network
                )
            changed = True
        return changed


    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        resource = self.client.api.tm.security.log.profiles.profile.load(
            name=self.want.name,
            partition=self.want.partition
        )
        if resource:
            resource.delete()

    def read_current_from_device(self):
        resource = self.client.api.tm.security.log.profiles.profile.load(
            name=self.want.name,
            partition=self.want.partition,
            requests_params=dict(
                params='expandSubcollections=true'
            )
        )
        result = resource.attrs
        return ApiParameters(params=result)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            description=dict(),
            network_firewall=dict(
                type='dict',
                options=dict(
                    publisher=dict(),
                    log_matches_accept_rule=dict(
                        type='dict',
                        options=dict(
                            enabled=dict(type='bool'),
                            rate_limit=dict()
                        )
                    ),
                    log_matches_drop_rule=dict(
                        type='dict',
                        options=dict(
                            enabled=dict(type='bool'),
                            rate_limit=dict()
                        )
                    ),
                    log_matches_reject_rule=dict(
                        type='dict',
                        options=dict(
                            enabled=dict(type='bool'),
                            rate_limit=dict()
                        )
                    ),
                    log_ip_errors=dict(
                        type='dict',
                        options=dict(
                            enabled=dict(type='bool'),
                            rate_limit=dict()
                        )
                    ),
                    log_tcp_errors=dict(
                        type='dict',
                        options=dict(
                            enabled=dict(type='bool'),
                            rate_limit=dict()
                        )
                    ),
                    log_tcp_events=dict(
                        type='dict',
                        options=dict(
                            enabled=dict(type='bool'),
                            rate_limit=dict()
                        )
                    ),
                    log_translation_fields=dict(type='bool'),
                    log_storage_format=dict(choices=['field-list', 'none']),
                    log_message_fields=dict(
                        type='list',
                        choices=[
                            "acl_policy_name",
                            "acl_policy_type",
                            "acl_rule_name",
                            "action",
                            "bigip_hostname",
                            "context_name",
                            "context_type",
                            "date_time",
                            "dest_fqdn",
                            "dest_geo",
                            "dest_ip",
                            "dest_port",
                            "drop_reason",
                            "management_ip_address",
                            "protocol",
                            "route_domain",
                            "sa_translation_pool",
                            "sa_translation_type",
                            "source_fqdn",
                            "source_user",
                            "src_geo",
                            "src_ip",
                            "src_port",
                            "translated_dest_ip",
                            "translated_dest_port",
                            "translated_ip_protocol",
                            "translated_route_domain",
                            "translated_src_ip",
                            "translated_src_port",
                            "translated_vlan",
                            "vlan"
                        ]
                    ),
                    log_format_delimiter=dict()
                )
            ),
            dos_protection=dict(
                type='dict',
                options=dict(
                    dns_publisher=dict()
                )
            ),
            ip_intelligence=dict(
                type='dict',
                options=dict(
                    publisher=dict(),
                    log_translation_fields=dict(type='bool')
                )
            ),
            state=dict(
                default='present',
                choices=['absent', 'present']
            ),
            partition=dict(
                default='Common',
                fallback=(env_fallback, ['F5_PARTITION'])
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )
    if not HAS_F5SDK:
        module.fail_json(msg="The python f5-sdk module is required")

    try:
        client = F5Client(**module.params)
        mm = ModuleManager(module=module, client=client)
        results = mm.exec_module()
        cleanup_tokens(client)
        module.exit_json(**results)
    except F5ModuleError as ex:
        cleanup_tokens(client)
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
