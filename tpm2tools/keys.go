package tpm2tools

import (
	"bytes"
	"crypto"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/server"
)

// Key wraps an active TPM2 key. Users of Key should be sure to call Close()
// when finished using the Key, so that the underlying TPM handle can be freed.
type Key struct {
	rw      io.ReadWriter
	handle  tpmutil.Handle
	pubArea tpm2.Public
	pubKey  crypto.PublicKey
	name    tpm2.Name
	session tpmutil.Handle
}

// EndorsementKeyRSA generates and loads a key from DefaultEKTemplateRSA.
func EndorsementKeyRSA(rw io.ReadWriter) (*Key, error) {
	return NewCachedKey(rw, tpm2.HandleEndorsement, DefaultEKTemplateRSA(), EKReservedHandle)
}

// EndorsementKeyECC generates and loads a key from DefaultEKTemplateECC.
func EndorsementKeyECC(rw io.ReadWriter) (*Key, error) {
	return NewKey(rw, tpm2.HandleEndorsement, DefaultEKTemplateECC())
}

// StorageRootKeyRSA generates and loads a key from SRKTemplateRSA.
func StorageRootKeyRSA(rw io.ReadWriter) (*Key, error) {
	return NewCachedKey(rw, tpm2.HandleOwner, SRKTemplateRSA(), SRKReservedHandle)
}

// StorageRootKeyECC generates and loads a key from SRKTemplateECC.
func StorageRootKeyECC(rw io.ReadWriter) (*Key, error) {
	return NewKey(rw, tpm2.HandleOwner, SRKTemplateECC())
}

// EndorsementKeyFromNvIndex generates and loads an endorsement key using the
// template stored at the provided nvdata index. This is useful for TPMs which
// have a preinstalled AIK template.
func EndorsementKeyFromNvIndex(rw io.ReadWriter, idx uint32) (*Key, error) {
	return KeyFromNvIndex(rw, tpm2.HandleEndorsement, idx)
}

// KeyFromNvIndex generates and loads a key under the provided parent
// (possibly a hierarchy root tpm2.Handle{Owner|Endorsement|Platform|Null})
// using the template stored at the provided nvdata index.
func KeyFromNvIndex(rw io.ReadWriter, parent tpmutil.Handle, idx uint32) (*Key, error) {
	data, err := tpm2.NVRead(rw, tpmutil.Handle(idx))
	if err != nil {
		return nil, fmt.Errorf("read error at index %d: %v", idx, err)
	}
	template, err := tpm2.DecodePublic(data)
	if err != nil {
		return nil, fmt.Errorf("index %d data was not a TPM key template: %v", idx, err)
	}
	return NewKey(rw, parent, template)
}

// NewCachedKey is almost identical to NewKey, except that it initially tries to
// see if the a key matching the provided template is at cachedHandle. If so,
// that key is returned. If not, the key is created as in NewKey, and that key
// is persisted to the cachedHandle, overwriting any existing key there.
func NewCachedKey(rw io.ReadWriter, parent tpmutil.Handle, template tpm2.Public, cachedHandle tpmutil.Handle) (k *Key, err error) {
	owner := tpm2.HandleOwner
	if parent == tpm2.HandlePlatform {
		owner = tpm2.HandlePlatform
	} else if parent == tpm2.HandleNull {
		return nil, fmt.Errorf("Cannot cache objects in the null hierarchy")
	}

	cachedPub, _, _, err := tpm2.ReadPublic(rw, cachedHandle)
	if err == nil {
		if cachedPub.MatchesTemplate(template) {
			k = &Key{rw: rw, handle: cachedHandle, pubArea: cachedPub}
			return k, k.finish()
		}
		// Kick out old cached key if it does not match
		if err = tpm2.EvictControl(rw, "", owner, cachedHandle, cachedHandle); err != nil {
			return nil, err
		}
	}

	k, err = NewKey(rw, parent, template)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(rw, k.handle)

	if err = tpm2.EvictControl(rw, "", owner, k.handle, cachedHandle); err != nil {
		return nil, err
	}
	k.handle = cachedHandle
	return k, nil
}

// NewKey generates a key from the template and loads that key into the TPM
// under the specified parent. NewKey can call many different TPM commands:
//   - If parent is tpm2.Handle{Owner|Endorsement|Platform|Null} a primary key
//     is created in the specified hierarchy (using CreatePrimary).
//   - If parent is a valid key handle, a normal key object is created under
//     that parent (using Create and Load). NOTE: Not yet supported.
// This function also assumes that the desired key:
//   - Does not have its usage locked to specific PCR values
//   - Usable with empty authorization sessions (i.e. doesn't need a password)
func NewKey(rw io.ReadWriter, parent tpmutil.Handle, template tpm2.Public) (k *Key, err error) {
	if !isHierarchy(parent) {
		// TODO add support for normal objects with Create() and Load()
		return nil, fmt.Errorf("unsupported parent handle: %x", parent)
	}

	handle, pubArea, _, _, _, _, err :=
		tpm2.CreatePrimaryEx(rw, parent, tpm2.PCRSelection{}, "", "", template)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			tpm2.FlushContext(rw, handle)
		}
	}()

	k = &Key{rw: rw, handle: handle}
	if k.pubArea, err = tpm2.DecodePublic(pubArea); err != nil {
		return
	}
	return k, k.finish()
}

func (k *Key) finish() error {
	var err error
	if k.pubKey, err = k.pubArea.Key(); err != nil {
		return err
	}
	if k.name, err = k.pubArea.Name(); err != nil {
		return err
	}
	if bytes.Equal(k.pubArea.AuthPolicy, defaultEKAuthPolicy()) {
		// EK uses Policy Authorization Session
		k.session, _, err = tpm2.StartAuthSession(
			k.rw,
			tpm2.HandleNull,  /*tpmKey*/
			tpm2.HandleNull,  /*bindKey*/
			make([]byte, 16), /*nonceCaller*/
			nil,              /*secret*/
			tpm2.SessionPolicy,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
	}
	return err
}

// Reauthorize performs any actions that must be done before using the key.
func (k *Key) Reauthorize() (tpm2.AuthCommand, error) {
	nullAuth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if bytes.Equal(k.pubArea.AuthPolicy, defaultEKAuthPolicy()) {
		_, err := tpm2.PolicySecret(k.rw, tpm2.HandleEndorsement, nullAuth, k.session, nil, nil, nil, 0)
		if err != nil {
			return tpm2.AuthCommand{}, fmt.Errorf("reauthorizing key: %v", err)
		}
		return tpm2.AuthCommand{Session: k.session, Attributes: tpm2.AttrContinueSession}, nil
	}
	return nullAuth, nil
}

// Handle allows this key to be used directly with other go-tpm commands.
func (k *Key) Handle() tpmutil.Handle {
	return k.handle
}

// Name is hash of this key's public area. Only the Digest field will ever be
// populated. It is useful for various TPM commands related to authorization.
func (k *Key) Name() tpm2.Name {
	return k.name
}

// PublicKey provides a go interface to the loaded key's public area.
func (k *Key) PublicKey() crypto.PublicKey {
	return k.pubKey
}

// Close should be called when the key is no longer needed. This is important to
// do as most TPMs can only have a small number of key simultaneously loaded.
func (k *Key) Close() {
	tpm2.FlushContext(k.rw, k.handle)
	if k.session != 0 {
		tpm2.FlushContext(k.rw, k.session)
	}
}

// ImportSecret decrypts a blob using TPM2_Import
func (k *Key) ImportSecret(data *proto.ImportData) ([]byte, error) {
	auth, err := k.Reauthorize()
	if err != nil {
		return nil, err
	}
	priv, err := tpm2.ImportUsingAuth(k.rw, k.handle, auth, data.Pub, data.Priv, data.OuterSeed, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Importing secret failed: %v", err)
	}
	return k.unsealHelper(data.Pub, priv, data.Pcrs)
}

// Seal seals the sensitive byte buffer to the provided PCRs under the owner
// hierarchy using the SHA256 versions of the provided PCRs.
// The Key k is used as the parent key.
func (k *Key) Seal(pcrs []int32, sensitive []byte) (*proto.SealedBytes, error) {
	auth, err := getPCRSessionAuth(k.rw, pcrs)
	if err != nil {
		return nil, fmt.Errorf("could not get pcr session auth: %v", err)
	}

	sb, err := sealHelper(k.rw, k.Handle(), auth, sensitive)
	if err != nil {
		return nil, err
	}
	sb.Pcrs = pcrs
	sb.Hash = proto.HashAlgo_SHA256
	sb.Srk = proto.ObjectType(k.pubArea.Type)
	return sb, nil
}

func sealHelper(rw io.ReadWriter, parentHandle tpmutil.Handle, auth []byte, sensitive []byte) (*proto.SealedBytes, error) {
	priv, pub, err := tpm2.Seal(rw, parentHandle, "", "", auth, sensitive)
	if err != nil {
		return nil, fmt.Errorf("failed to seal data: %v", err)
	}

	sb := proto.SealedBytes{}
	sb.Priv = priv
	sb.Pub = pub
	return &sb, nil
}

// Unseal takes a private/public pair of buffers and attempts to reverse the
// sealing process under the owner hierarchy using the SHA256 versions of the
// provided PCRs.
// The Key k is used as the parent key.
func (k *Key) Unseal(in *proto.SealedBytes) ([]byte, error) {
	if in.Srk != proto.ObjectType(k.pubArea.Type) {
		return nil, fmt.Errorf("Expected key of type %v, got %v", in.Srk, k.pubArea.Type)
	}
	if in.Hash != proto.HashAlgo_SHA256 {
		return nil, fmt.Errorf("Only SHA256 PCRs are currently supported")
	}
	return k.unsealHelper(in.Pub, in.Priv, in.Pcrs)
}

func (k *Key) unsealHelper(pub, priv []byte, pcrs []int32) ([]byte, error) {
	auth, err := k.Reauthorize()
	if err != nil {
		return nil, err
	}
	sealed, _, err := tpm2.LoadUsingAuth(k.rw, k.Handle(), auth, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed object: %v", err)
	}
	defer tpm2.FlushContext(k.rw, sealed)

	session, err := createPCRSession(k.rw, pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed create PCR session: %v", err)
	}
	defer tpm2.FlushContext(k.rw, session)

	secret, err := tpm2.UnsealWithSession(k.rw, session, sealed, "")
	if err != nil {
		return nil, fmt.Errorf("failed to unseal secret: %v", err)
	}
	return secret, nil
}

// Reseal unwraps a secret and rewraps it under the auth value that would be
// produced by the PCR state in pcrs. Similar to seal and unseal, this acts on
// the SHA256 PCRs and uses the owner hierarchy.
// The Key k is used as the parent key.
func (k *Key) Reseal(pcrs map[int32][]byte, in *proto.SealedBytes) (*proto.SealedBytes, error) {
	sensitive, err := k.Unseal(in)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal: %v", err)
	}

	sb, err := sealHelper(k.rw, k.Handle(), server.ComputePCRSessionAuth(pcrs), sensitive)
	if err != nil {
		return nil, err
	}
	for pcr := range pcrs {
		sb.Pcrs = append(sb.Pcrs, pcr)
	}
	sb.Hash = in.Hash
	sb.Srk = in.Srk
	return sb, nil
}

func getPCRSessionAuth(rw io.ReadWriter, pcrs []int32) ([]byte, error) {
	handle, err := createPCRSession(rw, pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %v", err)
	}
	defer tpm2.FlushContext(rw, handle)

	digest, err := tpm2.PolicyGetDigest(rw, handle)
	if err != nil {
		return nil, fmt.Errorf("could not get digest from session: %v", err)
	}

	return digest, nil
}

func createPCRSession(rw io.ReadWriter, pcrs []int32) (tpmutil.Handle, error) {
	nonceIn := make([]byte, 16)
	/* This session assumes the bus is trusted.  */
	handle, _, err := tpm2.StartAuthSession(
		rw,
		tpm2.HandleNull,
		tpm2.HandleNull,
		nonceIn,
		/*secret=*/ nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return tpm2.HandleNull, fmt.Errorf("failed to start auth session: %v", err)
	}

	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256}
	for _, pcr := range pcrs {
		sel.PCRs = append(sel.PCRs, int(pcr))
	}
	if err = tpm2.PolicyPCR(rw, handle, nil, sel); err != nil {
		return tpm2.HandleNull, fmt.Errorf("auth step PolicyPCR failed: %v", err)
	}

	return handle, nil
}
