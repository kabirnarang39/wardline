package adapter

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// kmsTimeout bounds every KMS API call this adapter makes -- GetPublicKey
// (construction only) and Sign (every token issuance) both sit on paths
// that must degrade to a bounded error rather than hang, same posture
// every network-backed adapter in this codebase already has
// (revokerTimeout, jwksBootstrapTimeout, ...). Sign is on the hot path
// (every /credentials/token bootstrap), so this is intentionally the
// same order of magnitude as those, not the multi-minute bound a batch
// operation would get.
const kmsTimeout = 5 * time.Second

// KMSClient is the subset of *kms.Client's behavior KMSSigner depends
// on -- a narrow interface (matching this codebase's established
// *Source/*Provisioner pattern) so tests can supply a fake without a
// real AWS account or the LocalStack-style KMS emulator this package's
// own integration tests use.
type KMSClient interface {
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMSSigner is a crypto.Signer whose RSA private key material never
// leaves AWS KMS -- Sign calls KMS's own Sign API for every signature
// (the sensitive operation stays in KMS/CloudHSM, never in this
// process's memory or a mounted Secret); Public returns a public key
// fetched once at construction and cached locally, so verification
// (Verify, JWKS) needs no KMS round trip at all, only issuing a new
// token does. Implements crypto.Signer, the exact extension point
// jwx/v3's jws package documents supporting natively ("crypto.Signer
// (e.g. KMS-backed adapters)") -- NewJWTIssuerVerifierWithSigner accepts
// this directly; nothing about Issue/Verify/JWKS/key-rotation needed to
// change to support it.
//
// This is the shipped AWS KMS implementation, not the only possible
// one: any other cloud KMS reachable via a Go crypto.Signer-shaped
// client (GCP Cloud KMS, Azure Key Vault) is a second, sibling adapter
// away, zero changes to JWTIssuerVerifier itself -- the same
// Open/Closed shape this codebase already uses for policy.Engine
// (OPA/Cedar/YAML) and domain.Bootstrapper (presharedsecret/OIDC/mTLS).
type KMSSigner struct {
	client KMSClient
	keyID  string
	pub    *rsa.PublicKey
}

// NewKMSSigner fetches keyID's public key from AWS KMS once, failing
// fast at construction (same posture as loadRSAPrivateKeyFile) rather
// than on the first token issuance. keyID must name an asymmetric KMS
// key with KeyUsage SIGN_VERIFY and KeySpec RSA_2048 or larger --
// GetPublicKey succeeds regardless of KeyUsage/KeySpec (it's a read-only
// describe-shaped call), so this adapter validates the returned key's
// actual type and size itself rather than trusting KMS to have rejected
// a mismatched key already.
func NewKMSSigner(ctx context.Context, client KMSClient, keyID string) (*KMSSigner, error) {
	getCtx, cancel := context.WithTimeout(ctx, kmsTimeout)
	defer cancel()
	out, err := client.GetPublicKey(getCtx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("fetch kms public key %s: %w", keyID, err)
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("kms key %s has KeyUsage %q, want SIGN_VERIFY", keyID, out.KeyUsage)
	}
	parsed, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse kms public key %s: %w", keyID, err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("kms key %s is not an RSA public key (got %T) -- credential.kms.key_id must name an asymmetric RSA SIGN_VERIFY key", keyID, parsed)
	}
	if bits := pub.N.BitLen(); bits < rsaKeyBits {
		return nil, fmt.Errorf("kms key %s is %d bits, minimum %d required for RS256 signing", keyID, bits, rsaKeyBits)
	}
	return &KMSSigner{client: client, keyID: keyID, pub: pub}, nil
}

// Public implements crypto.Signer.
func (s *KMSSigner) Public() crypto.PublicKey { return s.pub }

// Sign implements crypto.Signer. digest is the already-computed hash of
// the message (jwx/v3, like every crypto.Signer caller, hashes before
// calling Sign -- the standard crypto.Signer contract), so KMS's own
// Sign API is told MessageType: DIGEST to sign that hash directly
// rather than re-hashing the (unavailable here) original message.
// SigningAlgorithm is fixed to RSASSA_PKCS1_V1_5_SHA_256, matching
// RS256's own definition exactly (PKCS1v15 padding, not PSS) -- every
// existing RS256 verifier in this codebase (JWTIssuerVerifier.Verify,
// every JWKS consumer) must be able to verify a KMS-signed token
// identically to a local-key-signed one, so this has no PSS option to
// pick wrong.
func (s *KMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("kms signer only supports SHA-256 digests (RS256), got %v", opts.HashFunc())
	}
	ctx, cancel := context.WithTimeout(context.Background(), kmsTimeout)
	defer cancel()
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	return out.Signature, nil
}

var _ crypto.Signer = (*KMSSigner)(nil)
