package adapter

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// fakeKMSClient stands in for a real *kms.Client -- backed by a real
// in-process RSA key, so Sign produces a signature GetPublicKey's own
// returned key genuinely verifies, proving the digest/algorithm
// plumbing end to end without a real AWS account or a KMS emulator.
type fakeKMSClient struct {
	key           *rsa.PrivateKey
	keyUsage      types.KeyUsageType
	getPubErr     error
	signErr       error
	lastSignInput *kms.SignInput
	lastGetKeyID  string
}

func newFakeKMSClient(t *testing.T) *fakeKMSClient {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKMSClient{key: key, keyUsage: types.KeyUsageTypeSignVerify}
}

func (f *fakeKMSClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if f.getPubErr != nil {
		return nil, f.getPubErr
	}
	f.lastGetKeyID = *params.KeyId
	der, err := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, KeyUsage: f.keyUsage}, nil
}

func (f *fakeKMSClient) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	f.lastSignInput = params
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, params.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}

func TestNewKMSSigner_FetchesAndCachesPublicKey(t *testing.T) {
	client := newFakeKMSClient(t)
	s, err := NewKMSSigner(context.Background(), client, "test-key-id")
	if err != nil {
		t.Fatalf("NewKMSSigner: %v", err)
	}
	if client.lastGetKeyID != "test-key-id" {
		t.Errorf("expected GetPublicKey to be called with the configured key ID, got %q", client.lastGetKeyID)
	}
	pub, ok := s.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected Public() to return *rsa.PublicKey, got %T", s.Public())
	}
	if pub.N.Cmp(client.key.N) != 0 {
		t.Error("expected the cached public key to match the real KMS-side key")
	}
}

func TestNewKMSSigner_RejectsNonSignVerifyKey(t *testing.T) {
	client := newFakeKMSClient(t)
	client.keyUsage = types.KeyUsageTypeEncryptDecrypt
	if _, err := NewKMSSigner(context.Background(), client, "test-key-id"); err == nil {
		t.Fatal("expected an error for a key whose KeyUsage is not SIGN_VERIFY")
	}
}

func TestNewKMSSigner_RejectsUndersizedKey(t *testing.T) {
	client := newFakeKMSClient(t)
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	client.key = weakKey
	if _, err := NewKMSSigner(context.Background(), client, "test-key-id"); err == nil {
		t.Fatal("expected an error for an RSA key below the 2048-bit floor")
	}
}

func TestNewKMSSigner_PropagatesGetPublicKeyError(t *testing.T) {
	client := newFakeKMSClient(t)
	client.getPubErr = errors.New("kms unreachable")
	if _, err := NewKMSSigner(context.Background(), client, "test-key-id"); err == nil {
		t.Fatal("expected the GetPublicKey error to propagate")
	}
}

// TestKMSSigner_Sign_ProducesAVerifiableSignature is the actual proof:
// the signature KMSSigner.Sign returns verifies against the SAME
// public key Public() returns, using standard PKCS1v15/SHA-256
// verification -- exactly what JWTIssuerVerifier.Verify (and any real
// RS256 JWT verifier) does.
func TestKMSSigner_Sign_ProducesAVerifiableSignature(t *testing.T) {
	client := newFakeKMSClient(t)
	s, err := NewKMSSigner(context.Background(), client, "test-key-id")
	if err != nil {
		t.Fatalf("NewKMSSigner: %v", err)
	}

	message := []byte("the payload a real JWT signature covers")
	digest := sha256.Sum256(message)

	sig, err := s.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub := s.Public().(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("signature does not verify against the signer's own public key: %v", err)
	}

	if client.lastSignInput.MessageType != types.MessageTypeDigest {
		t.Errorf("expected MessageType DIGEST, got %v", client.lastSignInput.MessageType)
	}
	if client.lastSignInput.SigningAlgorithm != types.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
		t.Errorf("expected RSASSA_PKCS1_V1_5_SHA_256 (matching RS256), got %v", client.lastSignInput.SigningAlgorithm)
	}
}

func TestKMSSigner_Sign_RejectsNonSHA256Opts(t *testing.T) {
	client := newFakeKMSClient(t)
	s, err := NewKMSSigner(context.Background(), client, "test-key-id")
	if err != nil {
		t.Fatalf("NewKMSSigner: %v", err)
	}
	if _, err := s.Sign(nil, []byte("not-really-a-sha512-digest-but-length-doesnt-matter-here"), crypto.SHA512); err == nil {
		t.Fatal("expected an error for a non-SHA-256 SignerOpts (this codebase only supports RS256)")
	}
}

func TestKMSSigner_Sign_PropagatesKMSError(t *testing.T) {
	client := newFakeKMSClient(t)
	s, err := NewKMSSigner(context.Background(), client, "test-key-id")
	if err != nil {
		t.Fatalf("NewKMSSigner: %v", err)
	}
	client.signErr = errors.New("kms throttled")
	digest := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(nil, digest[:], crypto.SHA256); err == nil {
		t.Fatal("expected the KMS Sign error to propagate")
	}
}

// TestJWTIssuerVerifierWithSigner_IssuesAndVerifiesViaKMS is the
// end-to-end proof: JWTIssuerVerifier, wired with a KMSSigner instead
// of a local *rsa.PrivateKey, issues a real token and verifies it --
// zero changes to Issue/Verify's own logic, exactly the point of
// building this on crypto.Signer.
func TestJWTIssuerVerifierWithSigner_IssuesAndVerifiesViaKMS(t *testing.T) {
	client := newFakeKMSClient(t)
	signer, err := NewKMSSigner(context.Background(), client, "test-key-id")
	if err != nil {
		t.Fatalf("NewKMSSigner: %v", err)
	}

	iv, err := NewJWTIssuerVerifierWithSigner(signer, nil, 0)
	if err != nil {
		t.Fatalf("NewJWTIssuerVerifierWithSigner: %v", err)
	}
	iv.tokenTTL = 3600000000000 // 1h, avoids importing "time" just for this

	token, err := iv.Issue("alice", "acme")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := iv.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "alice" || claims.Tenant != "acme" {
		t.Errorf("got (%q, %q), want (\"alice\", \"acme\")", claims.Subject, claims.Tenant)
	}
}
