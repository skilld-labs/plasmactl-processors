package plasmactlprocessors

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/knadh/koanf"
	yamlparser "github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/action"
	vault "github.com/sosedoff/ansible-vault-go"
)

const ansibleVaultKeyringPrefix = "ansible-vault:"

type ansibleVault struct {
	content string
	koanf   *koanf.Koanf
	pass    string
}

func newAnsibleVault(content, pass string) ansibleVault {
	return ansibleVault{
		content: content,
		koanf:   koanf.New("."),
		pass:    pass,
	}
}

func (v *ansibleVault) get(key string) (string, error) {
	vy, err := vault.Decrypt(v.content, v.pass)
	if err != nil {
		return "", err
	}

	err = v.koanf.Load(rawbytes.Provider([]byte(vy)), yamlparser.Parser())
	if err != nil {
		return "", err
	}

	val := v.koanf.String(key)
	if val == "" {
		return "", fmt.Errorf("can't find key %q in the given ansible vault", key)
	}

	return val, nil
}

type ansibleVaultTemplateFunc struct {
	keyring keyring.Keyring
	action  *action.Action
}

func (p *ansibleVaultTemplateFunc) Get(filename, keypath string) (any, error) {
	keyringKey := ansibleVaultKeyringPrefix + filename
	absPath := filepath.ToSlash(filename)
	if !filepath.IsAbs(absPath) {
		absPath = filepath.Join(p.action.WorkDir(), absPath)
	}
	content, err := os.ReadFile(absPath) //nolint:gosec // G301 File inclusion is expected.
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("can't find ansible vault file %q", filename)
		}
		return nil, fmt.Errorf("can't read ansible vault file %q: %w", filename, err)
	}

	pass, err := p.keyring.GetForKey(keyringKey)
	if err != nil {
		if err == keyring.ErrNotFound {
			return nil, fmt.Errorf(
				"can't decrypt ansible vault file %q. Add an Ansible Vault file passphrase with `%s keyring:set %s`",
				filename, launchr.Version().Name, keyringKey,
			)
		}
		return nil, fmt.Errorf("can't decrypt ansible vault file %q: %w", filename, err)
	}

	av := newAnsibleVault(string(content), pass.Value.(string))
	v, err := av.get(keypath)
	if err != nil {
		return nil, fmt.Errorf("error on reading ansible vault file %q: %w", filename, err)
	}

	return v, nil
}
