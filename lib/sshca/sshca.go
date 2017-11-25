package sshca

import (
	"github.com/gravitational/teleport/lib/services"
)

// Authority implements minimal key-management facility for generating OpenSSH
// compatible public/private key pairs and OpenSSH certificates
type Authority interface {
	// GenerateKeyPair generates new keypair
	GenerateKeyPair(passphrase string) (privKey []byte, pubKey []byte, err error)

	// GetNewKeyPairFromPool returns new keypair from pre-generated in memory pool
	GetNewKeyPairFromPool() (privKey []byte, pubKey []byte, err error)

	// GenerateHostCert takes the private key of the CA, public key of the new host,
	// along with metadata (host ID, node name, cluster name, roles, and ttl) and generates
	// a host certificate.
	GenerateHostCert(certParams services.HostCertParams) ([]byte, error)

	// GenerateUserCert generates user certificate, it takes pkey as a signing
	// private key (user certificate authority)
	GenerateUserCert(certParams services.UserCertParams) ([]byte, error)
}
