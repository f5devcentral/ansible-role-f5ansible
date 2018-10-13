#!/usr/bin/env bash

DIR="$( cd "$( dirname "$( dirname "${BASH_SOURCE[0]}" )" )" >/dev/null && pwd )"

rm -rf /tmp/f5-ansible

# - download most recent copy of the upstream code
git clone https://github.com/F5Networks/f5-ansible.git /tmp/f5-ansible

# - replace action plugins
rm -rf ${DIR}/action_plugins
mv /tmp/f5-ansible/library/plugins/action ${DIR}/action_plugins
rm -f ${DIR}/action_plugins/__init__.py

# - replace library
rm -rf ${DIR}/library
mv /tmp/f5-ansible/library/modules ${DIR}/library
rm -f ${DIR}/library/__init__.py

# - remove modules that should not be part of the Galaxy role
rm -f ${DIR}/library/iworkflow*

# - replace module_utils
rm -rf ${DIR}/module_utils
mv /tmp/f5-ansible/library/module_utils ${DIR}/module_utils

# - replace terminal_plugins
rm -rf ${DIR}/terminal_plugins
mv /tmp/f5-ansible/library/plugins/terminal ${DIR}/terminal_plugins

echo "Finished merging changes from upstream"
echo "Commit, tag and push to update Galaxy"
