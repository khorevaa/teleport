package auth

import (
	"bytes"
	"crypto/rsa"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/tstranex/u2f"
)

type AuthenticateUserRequest struct {
	Username string                `json:"username"`
	Pass     *PassCreds            `json:"pass,omitempty"`
	U2F      *U2FSignResponseCreds `json:"u2f,omitempty"`
	OTP      *OTPCreds             `json:"otp,omitempty"`
	Session  *SessionCreds         `json:"session,omitempty"`
}

func (a *AuthenticateUserRequest) CheckAndSetDefaults() error {
	if a.Username == "" {
		return trace.BadParameter("missing parameter 'username'")
	}
	if a.Pass == nil && a.U2F == nil && a.OTP == nil {
		return trace.BadParameter("at least one authentication method is required")
	}
	return nil
}

type PassCreds struct {
	Password []byte `json:"password"`
}

type U2FSignResponseCreds struct {
	SignResponse u2f.SignResponse `json:"sign_response"`
}

type OTPCreds struct {
	Password []byte `json:"password"`
	Token    string `json:"token"`
}

type SessionCreds struct {
	ID string `json:"id"`
}

// AuthenticateUser authenticates user based on the request type
func (s *AuthServer) AuthenticateUser(req AuthenticateUserRequest) error {
	if err := req.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	authPreference, err := s.GetAuthPreference()
	if err != nil {
		return trace.Wrap(err)
	}

	switch {
	case req.Pass != nil:
		// authenticate using password only, make sure
		// that auth preference does not require second factor
		// otherwise users can bypass the second factor
		if authPreference.GetSecondFactor() != teleport.OFF {
			return trace.AccessDenied("missing second factor")
		}
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckPasswordWOToken(req.Username, req.Pass.Password)
		})
		if err != nil {
			// provide obscure message on purpose, while logging the real
			// error server side
			log.Debugf("failed to authenticate: %v", err)
			return trace.AccessDenied("invalid username or password")
		}
		return nil
	case req.U2F != nil:
		// authenticate using U2F - code checks challenge response
		// signed by U2F device of the user
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckU2FSignResponse(req.Username, &req.U2F.SignResponse)
		})
		if err != nil {
			// provide obscure message on purpose, while logging the real
			// error server side
			log.Debugf("failed to authenticate: %v", err)
			return trace.AccessDenied("invalid U2F response")
		}
		return nil
	case req.OTP != nil:
		err := s.WithUserLock(req.Username, func() error {
			return s.CheckPassword(req.Username, req.OTP.Password, req.OTP.Token)
		})
		if err != nil {
			// provide obscure message on purpose, while logging the real
			// error server side
			log.Debugf("failed to authenticate: %v", err)
			return trace.AccessDenied("invalid username, password or second factor")
		}
		return nil
	default:
		return trace.AccessDenied("unsupported authentication method")
	}
}

// AuthenticateWebUser authenticates web user, creates and  returns web session
// in case if authentication is successfull. In case if existing session id
// is used to authenticate, returns session associated with the existing session id
// instead of creating the new one
func (s *AuthServer) AuthenticateWebUser(req AuthenticateUserRequest) (services.WebSession, error) {
	if req.Session != nil {
		session, err := s.GetWebSession(req.Username, req.Session.ID)
		if err != nil {
			return nil, trace.AccessDenied("session is invalid or has expired")
		}
		return session, nil
	}
	if err := s.AuthenticateUser(req); err != nil {
		return nil, trace.Wrap(err)
	}
	sess, err := s.NewWebSession(req.Username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := s.UpsertWebSession(req.Username, sess); err != nil {
		return nil, trace.Wrap(err)
	}
	sess, err = services.GetWebSessionMarshaler().GenerateWebSession(sess)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return sess, nil
}

type AuthenticateSSHRequest struct {
	AuthenticateUserRequest
	// PublicKey is public key in ssh authorized_keys format
	PublicKey         []byte        `json:"public_key"`
	TTL               time.Duration `json:"ttl"`
	CompatibilityMode string        `json:"compatibility_mode"`
}

func (a *AuthenticateSSHRequest) CheckAndSetDefaults() error {
	if err := a.AuthenticateUserRequest.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if len(a.PublicKey) == 0 {
		return trace.BadParameter("missing parameter 'public_key'")
	}
	compatibility, err := utils.CheckCompatibilityFlag(a.CompatibilityMode)
	if err != nil {
		return trace.Wrap(err)
	}
	a.CompatibilityMode = compatibility
	return nil
}

// SSHLoginResponse is a response returned by web proxy, it preserves backwards compatibility
// on the wire, which is the primary reason for non-matching json tags
type SSHLoginResponse struct {
	// User contains a logged in user informationn
	Username string `json:"username"`
	// Cert is PEM encoded  signed certificate
	Cert []byte `json:"cert"`
	// TLSCertPEM is a PEM encoded TLS certificate signed by TLS certificate authority
	TLSCert []byte `json:"tls_cert"`
	// HostSigners is a list of signing host public keys trusted by proxy
	HostSigners []TrustedCerts `json:"host_signers"`
}

// TrustedCerts contains host certificates, it preserves backwards compatibility
// on the wire, which is the primary reason for non-matching json tags
type TrustedCerts struct {
	// ClusterName identifies teleport cluster name this authority serves,
	// for host authorities that means base hostname of all servers,
	// for user authorities that means organization name
	ClusterName string `json:"domain_name"`
	// HostCertificates is a list of SSH public keys that can be used to check
	// host certificate signatures
	HostCertificates [][]byte `json:"checking_keys"`
	// TLSCertificates  is a list of TLS certificates of the certificate authoritiy
	// of the authentication server
	TLSCertificates [][]byte `json:"tls_certs"`
}

// SSHCertPublicKeys returns a list of trusted host SSH certificate authority public keys
func (c *TrustedCerts) SSHCertPublicKeys() ([]ssh.PublicKey, error) {
	out := make([]ssh.PublicKey, 0, len(c.HostCertificates))
	for _, keyBytes := range c.HostCertificates {
		publicKey, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out = append(out, publicKey)
	}
	return out, nil
}

// AuthoritiesToTrustedCerts serializes authorities to TrustedCerts data structure
func AuthoritiesToTrustedCerts(authorities []services.CertAuthority) []TrustedCerts {
	out := make([]TrustedCerts, len(authorities))
	for i, ca := range authorities {
		out[i] = TrustedCerts{
			ClusterName:      ca.GetClusterName(),
			HostCertificates: ca.GetCheckingKeys(),
			TLSCertificates:  services.TLSCerts(ca),
		}
	}
	return out
}

// AuthenticateSSHUser authenticates web user, creates and  returns web session
// in case if authentication is successfull
func (s *AuthServer) AuthenticateSSHUser(req AuthenticateSSHRequest) (*SSHLoginResponse, error) {
	if err := s.AuthenticateUser(req.AuthenticateUserRequest); err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := s.GetUser(req.Username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roles, err := services.FetchRoles(user.GetRoles(), s, user.GetTraits())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	hostCertAuthorities, err := s.GetCertAuthorities(services.HostCA, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certs, err := s.generateUserCert(certRequest{
		user:          user,
		roles:         roles,
		ttl:           req.TTL,
		publicKey:     req.PublicKey,
		compatibility: req.CompatibilityMode,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &SSHLoginResponse{
		Username:    req.Username,
		Cert:        certs.ssh,
		TLSCert:     certs.tls,
		HostSigners: AuthoritiesToTrustedCerts(hostCertAuthorities),
	}, nil
}

type ExchangeCertsRequest struct {
	PublicKey []byte `json:"public_key"`
	TLSCert   []byte `json:"tls_cert"`
}

func (req *ExchangeCertsRequest) CheckAndSetDefaults() error {
	if len(req.PublicKey) == 0 {
		return trace.BadParameter("missing parameter 'public_key'")
	}
	if len(req.TLSCert) == 0 {
		return trace.BadParameter("missing parameter 'tls_cert'")
	}
	return nil
}

type ExchangeCertsResponse struct {
	TLSCert []byte `json:"tls_cert"`
}

func (s *AuthServer) ExchangeCerts(req ExchangeCertsRequest) (*ExchangeCertsResponse, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	remoteCA, err := s.findCertAuthorityByPublicKey(req.PublicKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := CheckPublicKeysEqual(req.PublicKey, req.TLSCert); err != nil {
		return nil, trace.Wrap(err)
	}

	remoteCA.SetTLSKeyPairs([]services.TLSKeyPair{
		{
			Cert: req.TLSCert,
		},
	})

	err = s.UpsertCertAuthority(remoteCA)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clusterName, err := s.GetClusterName()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	thisHostCA, err := s.GetCertAuthority(services.CertAuthID{Type: services.HostCA, DomainName: clusterName.GetClusterName()}, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &ExchangeCertsResponse{
		TLSCert: thisHostCA.GetTLSKeyPairs()[0].Cert,
	}, nil

}

func (s *AuthServer) findCertAuthorityByPublicKey(publicKey []byte) (services.CertAuthority, error) {
	authorities, err := s.GetCertAuthorities(services.HostCA, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for _, ca := range authorities {
		for _, key := range ca.GetCheckingKeys() {
			if bytes.Equal(key, publicKey) {
				return ca, nil
			}
		}
	}
	return nil, trace.NotFound("certificate authority with public key is not found")
}

// CheckPublicKeysEqual compares RSA based SSH public key with the public
// key in the TLS certificate, returns nil if keys are equal, error otherwise
func CheckPublicKeysEqual(sshKeyBytes []byte, certBytes []byte) error {
	cert, err := tlsca.ParseCertificatePEM(certBytes)
	if err != nil {
		return trace.Wrap(err)
	}
	certPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return trace.BadParameter("expected RSA public key, got %T", cert.PublicKey)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(sshKeyBytes)
	if err != nil {
		return trace.Wrap(err)
	}
	cryptoPubKey, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return trace.BadParameter("unexpected key type: %T", publicKey)
	}
	rsaPublicKey, ok := cryptoPubKey.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return trace.BadParameter("unexpected key type: %T", publicKey)
	}
	if certPublicKey.E != rsaPublicKey.E {
		return trace.CompareFailed("different public keys")
	}
	if certPublicKey.N.Cmp(rsaPublicKey.N) != 0 {
		return trace.CompareFailed("different public keys")
	}
	return nil
}
