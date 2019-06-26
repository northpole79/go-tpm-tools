package tpm2tools

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/internal"

	"github.com/davecgh/go-spew/spew"
)

func TestNameMatchesPublicArea(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)
	ek, err := EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()

	matches, err := ek.Name().MatchesPublic(ek.pubArea)
	if err != nil {
		t.Fatal(err)
	}
	if !matches {
		t.Fatal("Returned name and computed name do not match")
	}
}

func TestCreateSigningKeysInHierarchies(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)
	template := AIKTemplateRSA([256]byte{})

	// We are not authorized to create keys in the Platform Hierarchy
	for _, hierarchy := range []tpmutil.Handle{tpm2.HandleOwner, tpm2.HandleEndorsement, tpm2.HandleNull} {
		key, err := NewKey(rwc, hierarchy, template)
		if err != nil {
			t.Errorf("Hierarchy %+v: %s", hierarchy, err)
		} else {
			key.Close()
		}
	}
}

func TestImport(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	ek, err := EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()
	// EK uses Policy Authorization Session
	session, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession: %v", err)
	}
	defer tpm2.FlushContext(rwc, session)

	// Authorization w/ EK has to use Policy Secret sessions. Call
	// refreshSession, after each use of the EK using auth.
	refreshSession := func() {
		nullAuth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
		if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, nullAuth, session, nil, nil, nil, 0); err != nil {
			t.Fatalf("PolicySecret: %v", err)
		}
	}
	auth := tpm2.AuthCommand{Session: session, Attributes: tpm2.AttrContinueSession, Auth: nil}

	// Hash constants used thoughout
	hashAlg := ek.pubArea.NameAlg
	hash, err := hashAlg.HashConstructor()
	if err != nil {
		t.Fatalf("No hash algo: %s", err)
	}
	hashSize := hash().Size()

	// Make our random private key (Sensitive can be whatever length we want)
	private := tpm2.Private{
		Type:      tpm2.AlgKeyedHash,
		AuthValue: nil,
		SeedValue: make([]byte, hashSize),
		Sensitive: make([]byte, 18),
	}
	io.ReadFull(rand.Reader, private.SeedValue)
	io.ReadFull(rand.Reader, private.Sensitive)

	secret, err := private.Encode()
	if err != nil {
		t.Fatalf("Encoding secret failed: %s", err)
	}
	// TODO(joerichey) Understand why this second pack is needed
	packedSecret, err := tpmutil.Pack(tpmutil.U16Bytes(secret))
	if err != nil {
		t.Fatalf("Packing secret failed: %s", err)
	}

	// Compute the key's corresponding public area
	publicHash := hash()
	publicHash.Write(private.SeedValue)
	publicHash.Write(private.Sensitive)
	public := tpm2.Public{
		Type:            tpm2.AlgKeyedHash,
		NameAlg:         hashAlg,
		Attributes:      tpm2.FlagUserWithAuth,
		KeyedHashUnique: publicHash.Sum(nil),
	}
	pubEncoded, err := public.Encode()
	if err != nil {
		t.Fatalf("Encoding public failed: %s", err)
	}

	// The public area's name is used to compute the encryption key and HMAC.
	name, err := public.Name()
	if err != nil {
		t.Fatalf("Computing name failed: %s", err)
	}
	nameEncoded, err := name.Digest.Encode()
	if err != nil {
		t.Fatalf("Encoding name failed: %s", err)
	}

	// The seed length should match the size used by the EKs symmetric cipher.
	symBlockSize := ek.pubArea.RSAParameters.Symmetric.KeyBits / 8
	seed := make([]byte, symBlockSize)
	io.ReadFull(rand.Reader, seed)

	// Encrypt the seed value using the provided public key.
	label := append([]byte("DUPLICATE"), 0)
	encSeed, err := rsa.EncryptOAEP(hash(), rand.Reader, ek.PublicKey().(*rsa.PublicKey), seed, label)
	if err != nil {
		t.Fatalf("Encrypting Seed failed: %s", err)
	}
	// TODO(joerichey) Understand why this second pack is needed
	packedSeed, err := tpmutil.Pack(encSeed)
	if err != nil {
		t.Fatalf("Packing encSeed failed: %s", err)
	}

	// Generate the encrypted credential by convolving the seed with the public
	// name, and using the result as the key to encrypt the secret.
	symmetricKey, err := tpm2.KDFa(hashAlg, seed, "STORAGE", nameEncoded, nil, len(seed)*8)
	if err != nil {
		t.Fatalf("generating symmetric key: %v", err)
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		t.Fatalf("generating cipher: %v", err)
	}
	encSecret := make([]byte, len(packedSecret))
	iv := make([]byte, len(symmetricKey))
	cipher.NewCFBEncrypter(c, iv).XORKeyStream(encSecret, packedSecret)

	// Generate the integrity HMAC
	macKey, err := tpm2.KDFa(hashAlg, seed, "INTEGRITY", nil, nil, hashSize*8)
	if err != nil {
		t.Fatalf("generating mac key: %v", err)
	}
	mac := hmac.New(hash, macKey)
	mac.Write(encSecret)
	mac.Write(nameEncoded)

	// Create the encoded duplicate object
	duplicate, err := tpmutil.Pack(tpm2.IDObject{
		IntegrityHMAC: mac.Sum(nil),
		EncIdentity:   encSecret,
	})
	if err != nil {
		t.Fatalf("Encoding duplicate failed: %s", err)
	}

	refreshSession()
	privNew, err := tpm2.ImportUsingAuth(rwc, ek.Handle(), auth, pubEncoded, duplicate, packedSeed, nil, nil)
	if err != nil {
		t.Fatalf("Import failed: %s", err)
	}

	refreshSession()
	handle, _, err := tpm2.LoadUsingAuth(rwc, ek.Handle(), auth, pubEncoded, privNew)
	if err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, handle)

	out, err := tpm2.Unseal(rwc, handle, "")
	if err != nil {
		t.Fatalf("Unseal failed: %s", err)
	}
	if !bytes.Equal(out, private.Sensitive) {
		t.Errorf("Got %X, expected %X", out, private.Sensitive)
	}
}

func TestLoad(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	primaryKeyParams := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA1,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:  2048,
			Exponent: uint32(0x00010001),
			Modulus:  big.NewInt(0),
		},
	}

	interKeyParams := tpm2.Public{
		Type:    tpm2.AlgSymCipher,
		NameAlg: tpm2.AlgSHA1,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt,
		SymCipherParameters: &tpm2.SymCipherParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
		},
	}

	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{}}

	parentHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, "", "", primaryKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, parentHandle)

	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKey(rwc, parentHandle, pcrSelection, "", "", interKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %s", err)
	}

	keyHandle, _, err := tpm2.Load(rwc, parentHandle, "", publicBlob, privateBlob)
	if err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)

	if _, _, _, err := tpm2.ReadPublic(rwc, keyHandle); err != nil {
		t.Fatalf("ReadPublic failed: %s", err)
	}
}

func TestCreate(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	interKeyParams := tpm2.Public{
		Type:    tpm2.AlgSymCipher,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt,
		SymCipherParameters: &tpm2.SymCipherParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
		},
	}

	// Step a: Setup Policy Authorization Session
	session, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession: %v", err)
	}
	defer tpm2.FlushContext(rwc, session)

	// Step b: Configure EK hierarchy to use the session
	nullAuth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, nullAuth, session, nil, nil, nil, 0); err != nil {
		t.Fatalf("PolicySecret: %v", err)
	}

	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{}}

	parentHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, "", "", DefaultEKTemplateRSA())
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, parentHandle)

	auth := tpm2.AuthCommand{Session: session, Attributes: tpm2.AttrContinueSession, Auth: nil}
	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKeyUsingAuth(rwc, parentHandle, pcrSelection, auth, "", interKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %s", err)
	}

	// Step b: Configure EK hierarchy to use the session
	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, nullAuth, session, nil, nil, nil, 0); err != nil {
		t.Fatalf("PolicySecret: %v", err)
	}

	keyHandle, _, err := tpm2.LoadUsingAuth(rwc, parentHandle, auth, publicBlob, privateBlob)
	if err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)

	if _, _, _, err := tpm2.ReadPublic(rwc, keyHandle); err != nil {
		t.Fatalf("ReadPublic failed: %s", err)
	}

}

func TestBinding(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	interKeyParams := tpm2.Public{
		Type:    tpm2.AlgSymCipher,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt,
		SymCipherParameters: &tpm2.SymCipherParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
		},
	}

	// Step a: Setup Policy Authorization Session
	session, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession: %v", err)
	}
	defer tpm2.FlushContext(rwc, session)

	// Step b: Configure EK hierarchy to use the session
	nullAuth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, nullAuth, session, nil, nil, nil, 0); err != nil {
		t.Fatalf("PolicySecret: %v", err)
	}

	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{}}

	parentHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, "", "", DefaultEKTemplateRSA())
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, parentHandle)

	auth := tpm2.AuthCommand{Session: session, Attributes: tpm2.AttrContinueSession, Auth: nil}
	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKeyUsingAuth(rwc, parentHandle, pcrSelection, auth, "", interKeyParams)
	if err != nil {
		t.Fatalf("CreateKey failed: %s", err)
	}

	// Step b: Configure EK hierarchy to use the session
	if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, nullAuth, session, nil, nil, nil, 0); err != nil {
		t.Fatalf("PolicySecret: %v", err)
	}

	inPriv := bytes.NewBuffer(privateBlob)

	var priv tpm2.Private
	err = tpmutil.UnpackBuf(inPriv, &priv)
	if err != nil {
		t.Fatalf("decode private failed: %s", err)
	}
	spew.Dump(priv)

	pub, err := tpm2.DecodePublic(publicBlob)
	if err != nil {
		t.Fatalf("decode public failed: %s", err)
	}

	spew.Dump(pub)
	pub.SymCipherParameters.Unique[0]++
	publicBlob, err = pub.Encode()
	if err != nil {
		t.Fatalf("rencode public failed: %s", err)
	}

	keyHandle, _, err := tpm2.LoadUsingAuth(rwc, parentHandle, auth, publicBlob, privateBlob)
	if err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rwc, keyHandle)

	if _, _, _, err := tpm2.ReadPublic(rwc, keyHandle); err != nil {
		t.Fatalf("ReadPublic failed: %s", err)
	}

}

func BenchmarkEndorsementKeyRSA(b *testing.B) {
	b.StopTimer()
	rwc := internal.GetTPM(b)
	defer CheckedClose(b, rwc)
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		key, err := EndorsementKeyRSA(rwc)
		if err != nil {
			b.Fatal(err)
		}
		key.Close()
	}
}

func BenchmarkStorageRootKeyRSA(b *testing.B) {
	b.StopTimer()
	rwc := internal.GetTPM(b)
	defer CheckedClose(b, rwc)
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		key, err := StorageRootKeyRSA(rwc)
		if err != nil {
			b.Fatal(err)
		}
		key.Close()
	}
}

func BenchmarkNullSigningKeyRSA(b *testing.B) {
	b.StopTimer()
	rwc := internal.GetTPM(b)
	defer CheckedClose(b, rwc)
	template := AIKTemplateRSA([256]byte{})
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		key, err := NewKey(rwc, tpm2.HandleNull, template)
		if err != nil {
			b.Fatal(err)
		}
		key.Close()
	}
}
