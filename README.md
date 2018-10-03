# f5devcentral.f5ansible

Using this role, you will be able to use the latest version, and version specific F5 Networks
Ansible Modules.

## Requirements

 - python >= 2.7
 - f5-sdk

This role requires Ansible 2.7 or higher. Requirements are listed in the metadata file.

Please install f5-sdk from pip prior to running this module.
```

pip install f5-sdk --upgrade
```

## Installation

To install the F5 Networks Ansible Role, please issue the command on the machine you will
run Ansible from.
```

ansible-galaxy install -f f5devcentral.f5ansible
```

For more information please visit http://docs.ansible.com/ansible/galaxy.html

## Role Variables



## Example Playbooks

The following example is generic, applies to any module.

```
---
- hosts: localhost
  connection: local

  roles:
    - role: f5devcentral.f5ansible

  tasks:
    - name: Some task
      bigip_<module_name>:
        provider:
          server: 1.1.1.1
          user: admin
          password: secret
      ......
```

This example shows usage of the avi_healthmonitor module included in this role.

```
---
- hosts: localhost
  connection: local
  roles:
    - role: avinetworks.avisdk
  tasks:
    - avi_healthmonitor:
        controller: 10.10.27.90
        username: admin
        password: password
        api_version: 17.1
        https_monitor:
          http_request: HEAD / HTTP/1.0
          http_response_code:
            - HTTP_2XX
            - HTTP_3XX
        receive_timeout: 4
        failed_checks: 3
        send_interval: 10
        successful_checks: 3
        type: HEALTH_MONITOR_HTTPS
        name: MyWebsite-HTTPS
```

There are many more examples located at in the ``EXAMPLES`` within each module.

## License

Apache 2.0

## Author Information

F5 Networks
[f5 Networks](http://www.f5.com)
