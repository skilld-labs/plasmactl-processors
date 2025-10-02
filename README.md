# plasmactl-processors

A [Launchr](https://github.com/launchrctl/launchr) plugin that provides template processors for enhanced action functionality.

## Features

### Ansible Vault Template Function

Decrypt and extract values from Ansible Vault files using dot-notation key paths.

**Usage in Action Definition:**

```yaml
action:
  title: Example with Ansible Vault
runtime:
  type: container
  image: alpine
  command:
    - '{{ AnsibleVault "path/to/vault.yaml" "foo.bar" }}'
```

**Setup:**
Store your Ansible Vault passphrase securely using [Keyring](https://github.com/launchrctl/keyring):

``` bash
plasmactl keyring:set "ansible-vault:path/to/vault.yaml"
```
