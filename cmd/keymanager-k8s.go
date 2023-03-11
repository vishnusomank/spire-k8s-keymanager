package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"sync"

	keymanagerv1 "github.com/accuknox/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	configv1 "github.com/accuknox/spire-plugin-sdk/proto/spire/service/common/config/v1"
	keymanagerbase "github.com/accuknox/spire/pkg/agent/plugin/keymanager/base"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config defines the configuration for the plugin.
type Config struct {
	Namespace  string `hcl:"namespace"`
	SecretName string `hcl:"secretname"`
}

// Plugin implements the K8s KeyManager plugin
type Plugin struct {
	*keymanagerbase.Base
	keymanagerv1.UnimplementedKeyManagerServer
	configv1.UnimplementedConfigServer
	configMtx sync.RWMutex
	config    *Config
	logger    hclog.Logger
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// GenerateKey implements the KeyManager GenerateKey RPC
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	// TODO: Implement the RPC behavior. The following line silences compiler
	// warnings and can be removed once the configuration is referenced by the
	// implementation.
	config = config

	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// GetPublicKey implements the KeyManager GetPublicKey RPC
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	// TODO: Implement the RPC behavior. The following line silences compiler
	// warnings and can be removed once the configuration is referenced by the
	// implementation.
	config = config

	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// GetPublicKeys implements the KeyManager GetPublicKeys RPC
func (p *Plugin) GetPublicKeys(ctx context.Context, req *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	// TODO: Implement the RPC behavior. The following line silences compiler
	// warnings and can be removed once the configuration is referenced by the
	// implementation.
	config = config

	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// SignData implements the KeyManager SignData RPC
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	// TODO: Implement the RPC behavior. The following line silences compiler
	// warnings and can be removed once the configuration is referenced by the
	// implementation.
	config = config

	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func getDefaultNamespace() string {
	return "spire"
}

func getDefaultSecretName() string {
	return "spire-agent-secret"
}

// Configure configures the plugin. This is invoked by SPIRE when the plugin is
// first loaded. In the future, tt may be invoked to reconfigure the plugin.
// As such, it should replace the previous configuration atomically.
// TODO: Remove if no configuration is required
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	if config.Namespace == "" {
		config.Namespace = getDefaultNamespace()
	}
	if config.SecretName == "" {
		config.SecretName = getDefaultSecretName()
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

// setConfig replaces the configuration atomically under a write lock.
func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

// getConfig gets the configuration under a read lock.
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *Plugin) writeEntries(ctx context.Context, allEntries []*keymanagerbase.KeyEntry, newEntry *keymanagerbase.KeyEntry) error {
	p.configMtx.Lock()
	config := p.config
	p.configMtx.Unlock()

	if config == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	return writeEntries(config.Namespace, config.SecretName, allEntries)
}

type entriesData struct {
	Keys map[string][]byte `json:"keys"`
}

func writeEntries(namespace string, secretname string, entries []*keymanagerbase.KeyEntry) error {
	data := &entriesData{
		Keys: make(map[string][]byte),
	}
	for _, entry := range entries {
		keyBytes, err := x509.MarshalPKCS8PrivateKey(entry.PrivateKey)
		if err != nil {
			return err
		}
		data.Keys[entry.Id] = keyBytes
	}

	jsonBytes, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal entries: %v", err)
	}

	if err := CreateK8sSecrets(namespace, secretname, jsonBytes); err != nil {
		return status.Errorf(codes.Internal, "unable to write entries: %v", err)
	}
	return nil
}
