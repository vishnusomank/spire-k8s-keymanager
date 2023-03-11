package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
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

var log hclog.Logger

// Plugin implements the K8s KeyManager plugin
type Plugin struct {
	keymanagerv1.UnimplementedKeyManagerServer
	configv1.UnimplementedConfigServer
	mu     sync.RWMutex
	config *Config
	logger hclog.Logger
	base   *keymanagerbase.Base
}

type Generator = keymanagerbase.Generator

func New(generator Generator) *Plugin {
	return newKeyManager(generator)
}

func newKeyManager(generator Generator) *Plugin {

	p := &Plugin{}
	p.base = keymanagerbase.New(keymanagerbase.Config{
		Generator:    generator,
		WriteEntries: p.writeEntries,
	})

	return p
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
	log = logger
}

func getDefaultNamespace() string {
	return "spire"
}

func getDefaultSecretName() string {
	return "spire-agent-secret"
}

// Configure configures the plugin. This is invoked by SPIRE when the plugin is
// first loaded. In the future, it may be invoked to reconfigure the plugin.
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

	if err := p.configure(config); err != nil {
		return nil, err
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

// setConfig replaces the configuration atomically under a write lock.
func (p *Plugin) setConfig(config *Config) {
	p.mu.Lock()
	p.config = config
	p.mu.Unlock()
}

func (p *Plugin) configure(config *Config) error {
	// Only load entry information on first configure
	if p.config == nil {
		if err := p.loadEntries(config.Namespace, config.SecretName); err != nil {
			return err
		}
	}
	return nil
}

func (p *Plugin) writeEntries(ctx context.Context, allEntries []*keymanagerbase.KeyEntry, newEntry *keymanagerbase.KeyEntry) error {
	p.logger.Info("Writing agent private key to k8s secrets")
	p.mu.Lock()
	config := p.config
	p.mu.Unlock()

	if config == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	return writeEntries(config.Namespace, config.SecretName, allEntries)
}

func (p *Plugin) loadEntries(namespace, secretname string) error {
	// Load the entries from the keys file.
	p.logger.Info("Loading agent private key from secrets")
	entries, err := loadEntries(namespace, secretname)
	if err != nil {
		return err
	}

	p.base.SetEntries(entries)

	return nil
}

// GenerateKey implements the KeyManager GenerateKey RPC
func (p *Plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	return p.base.GenerateKey(ctx, req)

}

// GetPublicKey implements the KeyManager GetPublicKey RPC
func (p *Plugin) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {

	return p.base.GetPublicKey(ctx, req)
}

// GetPublicKeys implements the KeyManager GetPublicKeys RPC
func (p *Plugin) GetPublicKeys(ctx context.Context, req *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	return p.base.GetPublicKeys(ctx, req)
}

// SignData implements the KeyManager SignData RPC
func (p *Plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	return p.base.SignData(ctx, req)
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
		log.Error("unable to marshal entries: %v", err)
		return status.Errorf(codes.Internal, "unable to marshal entries: %v", err)
	}

	if err := CreateK8sSecrets(namespace, secretname, jsonBytes); err != nil {
		log.Error("unable to write entries: %v", err)
		return status.Errorf(codes.Internal, "unable to write entries: %v", err)
	}
	return nil
}

func loadEntries(namespace, secretname string) ([]*keymanagerbase.KeyEntry, error) {

	secret, err := GetK8sSecrets(namespace, secretname)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			log.Warn("no secrets found")
			return nil, nil
		}
		log.Error("unable to get secret: %v", err)
		return nil, err
	}

	jsonBytes, ok := secret.Data[secretname]
	if !ok {
		log.Error("unable to get agent private key from secret: %v", err)
		return nil, fmt.Errorf("failed to get agent private key from secret")
	}

	data := new(entriesData)

	if err := json.Unmarshal(jsonBytes, data); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to decode keys JSON: %v", err)
	}

	var entries []*keymanagerbase.KeyEntry
	for id, keyBytes := range data.Keys {
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to parse key %q: %v", id, err)
		}

		entry, err := keymanagerbase.MakeKeyEntryFromKey(id, key)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to make entry %q: %v", id, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
