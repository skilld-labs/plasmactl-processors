package plasmactlprocessors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/launchrctl/keyring"
	"github.com/launchrctl/launchr"
	"github.com/launchrctl/launchr/pkg/action"
	vault "github.com/sosedoff/ansible-vault-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTplAnsibleVaultValid = `
action:
  title: test keyring
  options:
    - name: vault-path
      default: "foo/vault.yaml"
runtime:
  type: container
  image: alpine
  command:
    - '{{ AnsibleVault .vault_path "foo.bar" }}'
`

const testTplAnsibleVaultKeyMiss = `
action:
  title: test keyring
  options:
    - name: vault-path
      default: "foo/vault.yaml"
runtime:
  type: container
  image: alpine
  command:
    - '{{ AnsibleVault .vault_path "foo.buz" }}'
`

const testTplAnsibleVaultFileNotFound = `
action:
  title: test keyring
  options:
    - name: vault-path
      default: "foo/no-vault.yaml"
runtime:
  type: container
  image: alpine
  command:
    - '{{ AnsibleVault .vault_path "foo.bar" }}'
`

const testTplAnsibleVaultKeyringNotFound = `
action:
  title: test keyring
  options:
    - name: vault-path
      default: "foo/vault2.yaml"
runtime:
  type: container
  image: alpine
  command:
    - '{{ AnsibleVault .vault_path "foo.bar" }}'
`

const testTplAnsibleVaultBadArgs = `
action:
  title: test keyring
runtime:
  type: container
  image: alpine
  command:
    - '{{ AnsibleVault "1" "2" "3" }}'
`

const testVaultPass = "MyVaultPass123!"
const testVaultContent = `
foo:
  bar: my_secret
`

func Test_AnsibleVaultTemplate(t *testing.T) {
	// Prepare services.
	k := keyring.NewService(keyring.NewFileStore(nil), nil)
	tp := action.NewTemplateProcessors()
	svc := launchr.NewServiceManager()
	svc.Add(tp)
	svc.Add(k)
	addTemplateProcessors(tp, k)

	// Prepare test data.
	wd := t.TempDir()
	vaultsDir := "foo"
	err := os.MkdirAll(filepath.Join(wd, vaultsDir), 0750)
	require.NoError(t, err)
	vaultPath1 := filepath.Join(vaultsDir, "vault.yaml")
	vaultPath2 := filepath.Join(vaultsDir, "vault2.yaml")

	// Create temporary vault files.
	err = vault.EncryptFile(filepath.Join(wd, vaultPath1), testVaultContent, testVaultPass)
	require.NoError(t, err)
	err = vault.EncryptFile(filepath.Join(wd, vaultPath2), testVaultContent, testVaultPass)
	require.NoError(t, err)

	// Set keyring with vault passphrase.
	err = k.AddItem(keyring.KeyValueItem{Key: ansibleVaultKeyringPrefix + filepath.ToSlash(vaultPath1), Value: testVaultPass})
	require.NoError(t, err)

	type testCase struct {
		Name string
		Yaml string
		Exp  []string
		Err  string
	}
	tt := []testCase{
		{Name: "valid", Yaml: testTplAnsibleVaultValid, Exp: []string{"my_secret"}},
		{Name: "key miss in vault", Yaml: testTplAnsibleVaultKeyMiss, Err: "error on reading ansible vault file \"foo/vault.yaml\": can't find key \"foo.buz\" in the given ansible vault"},
		{Name: "file not found", Yaml: testTplAnsibleVaultFileNotFound, Err: "can't find ansible vault file \"foo/no-vault.yaml\""},
		{Name: "keyring no vault passphrase", Yaml: testTplAnsibleVaultKeyringNotFound, Err: "AnsibleVault: can't decrypt ansible vault file \"foo/vault2.yaml\". Add an Ansible Vault file passphrase with"},
		{Name: "wrong call", Yaml: testTplAnsibleVaultBadArgs, Err: "wrong number of args for AnsibleVault: want 2 got 3"},
	}

	require.NoError(t, err)
	for _, tt := range tt {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			a := action.NewFromYAML(tt.Name, []byte(tt.Yaml))
			a.SetWorkDir(wd)
			a.SetServices(svc)
			err := a.EnsureLoaded()
			if tt.Err != "" {
				require.ErrorContains(t, err, tt.Err)
				return
			}
			require.NoError(t, err)
			rdef := a.RuntimeDef()
			assert.Equal(t, tt.Exp, []string(rdef.Container.Command))
		})
	}
}
