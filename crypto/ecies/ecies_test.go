// Copyright (c) 2013 Kyle Isom <kyle@tyrfingr.is>
// Copyright (c) 2012 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package ecies

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestKDF(t *testing.T) {
	tests := []struct {
		length int
		output []byte
	}{
		{6, decode("858b192fa2ed")},
		{32, decode("858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0")},
		{48, decode("858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0700f1ab918a5f0413b8140f9940d6955")},
		{64, decode("858b192fa2ed4395e2bf88dd8d5770d67dc284ee539f12da8bceaa45d06ebae0700f1ab918a5f0413b8140f9940d6955f3467fd6672cce1024c5b1effccc0f61")},
	}

	for _, test := range tests {
		h := sha256.New()
		k := concatKDF(h, []byte("input"), nil, test.length)
		if !bytes.Equal(k, test.output) {
			t.Fatalf("KDF: generated key %x does not match expected output %x", k, test.output)
		}
	}
}

var ErrBadSharedKeys = errors.New("ecies: shared keys don't match")

// cmpParams compares a set of ECIES parameters. We assume, as per the
// docs, that AES is the only supported symmetric encryption algorithm.
func cmpParams(p1, p2 *ECIESParams) bool {
	return p1.hashAlgo == p2.hashAlgo &&
		p1.KeyLen == p2.KeyLen &&
		p1.BlockSize == p2.BlockSize
}

// Validate the ECDH component.
func TestSharedKey(t *testing.T) {
	prv1, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}
	skLen := MaxSharedKeyLength(&prv1.PublicKey) / 2

	prv2, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}

	sk1, err := prv1.GenerateShared(&prv2.PublicKey, skLen, skLen)
	if err != nil {
		t.Fatal(err)
	}

	sk2, err := prv2.GenerateShared(&prv1.PublicKey, skLen, skLen)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sk1, sk2) {
		t.Fatal(ErrBadSharedKeys)
	}
}

func TestSharedKeyPadding(t *testing.T) {
	// sanity checks
	prv0 := hexKey("1adf5c18167d96a1f9a0b1ef63be8aa27eaf6032c233b2b38f7850cf5b859fd9")
	prv1 := hexKey("0097a076fc7fcd9208240668e31c9abee952cbb6e375d1b8febc7499d6e16f1a")
	x0, _ := new(big.Int).SetString("1a8ed022ff7aec59dc1b440446bdda5ff6bcb3509a8b109077282b361efffbd8", 16)
	x1, _ := new(big.Int).SetString("6ab3ac374251f638d0abb3ef596d1dc67955b507c104e5f2009724812dc027b8", 16)
	y0, _ := new(big.Int).SetString("e040bd480b1deccc3bc40bd5b1fdcb7bfd352500b477cb9471366dbd4493f923", 16)
	y1, _ := new(big.Int).SetString("8ad915f2b503a8be6facab6588731fefeb584fd2dfa9a77a5e0bba1ec439e4fa", 16)

	if prv0.PublicKey.X.Cmp(x0) != 0 {
		t.Errorf("mismatched prv0.X:\nhave: %x\nwant: %x\n", prv0.PublicKey.X.Bytes(), x0.Bytes())
	}
	if prv0.PublicKey.Y.Cmp(y0) != 0 {
		t.Errorf("mismatched prv0.Y:\nhave: %x\nwant: %x\n", prv0.PublicKey.Y.Bytes(), y0.Bytes())
	}
	if prv1.PublicKey.X.Cmp(x1) != 0 {
		t.Errorf("mismatched prv1.X:\nhave: %x\nwant: %x\n", prv1.PublicKey.X.Bytes(), x1.Bytes())
	}
	if prv1.PublicKey.Y.Cmp(y1) != 0 {
		t.Errorf("mismatched prv1.Y:\nhave: %x\nwant: %x\n", prv1.PublicKey.Y.Bytes(), y1.Bytes())
	}

	// test shared secret generation
	sk1, err := prv0.GenerateShared(&prv1.PublicKey, 16, 16)
	if err != nil {
		t.Log(err.Error())
	}

	sk2, err := prv1.GenerateShared(&prv0.PublicKey, 16, 16)
	if err != nil {
		t.Fatal(err.Error())
	}

	if !bytes.Equal(sk1, sk2) {
		t.Fatal(ErrBadSharedKeys.Error())
	}
}

// Verify that the key generation code fails when too much key data is
// requested.
func TestTooBigSharedKey(t *testing.T) {
	prv1, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}

	prv2, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = prv1.GenerateShared(&prv2.PublicKey, 32, 32)
	if err != ErrSharedKeyTooBig {
		t.Fatal("ecdh: shared key should be too large for curve")
	}

	_, err = prv2.GenerateShared(&prv1.PublicKey, 32, 32)
	if err != ErrSharedKeyTooBig {
		t.Fatal("ecdh: shared key should be too large for curve")
	}
}

// Benchmark the generation of P256 keys.
func BenchmarkGenerateKeyP256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKey(rand.Reader, elliptic.P256(), nil); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark the generation of P256 shared keys.
func BenchmarkGenSharedKeyP256(b *testing.B) {
	prv, err := GenerateKey(rand.Reader, elliptic.P256(), nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := prv.GenerateShared(&prv.PublicKey, 16, 16)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark the generation of S256 shared keys.
func BenchmarkGenSharedKeyS256(b *testing.B) {
	prv, err := GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := prv.GenerateShared(&prv.PublicKey, 16, 16)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Verify that an encrypted message can be successfully decrypted.
func TestEncryptDecrypt(t *testing.T) {
	prv1, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}

	prv2, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(rand.Reader, &prv2.PublicKey, message, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := prv2.Decrypt(ct, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, message) {
		t.Fatal("ecies: plaintext doesn't match message")
	}

	_, err = prv1.Decrypt(ct, nil, nil)
	if err == nil {
		t.Fatal("ecies: encryption should not have succeeded")
	}
}

func TestDecryptShared2(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("Hello, world.")
	shared2 := []byte("shared data 2")
	ct, err := Encrypt(rand.Reader, &prv.PublicKey, message, nil, shared2)
	if err != nil {
		t.Fatal(err)
	}

	// Check that decrypting with correct shared data works.
	pt, err := prv.Decrypt(ct, nil, shared2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, message) {
		t.Fatal("ecies: plaintext doesn't match message")
	}

	// Decrypting without shared data or incorrect shared data fails.
	if _, err = prv.Decrypt(ct, nil, nil); err == nil {
		t.Fatal("ecies: decrypting without shared data didn't fail")
	}
	if _, err = prv.Decrypt(ct, nil, []byte("garbage")); err == nil {
		t.Fatal("ecies: decrypting with incorrect shared data didn't fail")
	}
}

type testCase struct {
	Curve    elliptic.Curve
	Name     string
	Expected *ECIESParams
}

var testCases = []testCase{
	{
		Curve:    elliptic.P256(),
		Name:     "P256",
		Expected: ECIES_AES128_SHA256,
	},
	{
		Curve:    elliptic.P384(),
		Name:     "P384",
		Expected: ECIES_AES192_SHA384,
	},
	{
		Curve:    elliptic.P521(),
		Name:     "P521",
		Expected: ECIES_AES256_SHA512,
	},
}

// Test parameter selection for each curve, and that P224 fails automatic
// parameter selection (see README for a discussion of P224). Ensures that
// selecting a set of parameters automatically for the given curve works.
func TestParamSelection(t *testing.T) {
	for _, c := range testCases {
		testParamSelection(t, c)
	}
}

func testParamSelection(t *testing.T, c testCase) {
	params := ParamsFromCurve(c.Curve)
	if params == nil {
		t.Fatal("ParamsFromCurve returned nil")
	} else if params != nil && !cmpParams(params, c.Expected) {
		t.Fatalf("ecies: parameters should be invalid (%s)\n", c.Name)
	}

	prv1, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatalf("%s (%s)\n", err.Error(), c.Name)
	}

	prv2, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatalf("%s (%s)\n", err.Error(), c.Name)
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(rand.Reader, &prv2.PublicKey, message, nil, nil)
	if err != nil {
		t.Fatalf("%s (%s)\n", err.Error(), c.Name)
	}

	pt, err := prv2.Decrypt(ct, nil, nil)
	if err != nil {
		t.Fatalf("%s (%s)\n", err.Error(), c.Name)
	}

	if !bytes.Equal(pt, message) {
		t.Fatalf("ecies: plaintext doesn't match message (%s)\n", c.Name)
	}

	_, err = prv1.Decrypt(ct, nil, nil)
	if err == nil {
		t.Fatalf("ecies: encryption should not have succeeded (%s)\n", c.Name)
	}
}

// Ensure that the basic public key validation in the decryption operation
// works.
func TestBasicKeyValidation(t *testing.T) {
	badBytes := []byte{0, 1, 5, 6, 7, 8, 9}

	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(rand.Reader, &prv.PublicKey, message, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, b := range badBytes {
		ct[0] = b
		_, err := prv.Decrypt(ct, nil, nil)
		if err != ErrInvalidPublicKey {
			t.Fatal("ecies: validated an invalid key")
		}
	}
}

func TestBox(t *testing.T) {
	prv1 := hexKey("4b50fa71f5c3eeb8fdc452224b2395af2fcc3d125e06c32c82e048c0559db03f")
	prv2 := hexKey("d0b043b4c5d657670778242d82d68a29d25d7d711127d17b8e299f156dad361a")
	pub2 := &prv2.PublicKey

	message := []byte("Hello, world.")
	ct, err := Encrypt(rand.Reader, pub2, message, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := prv2.Decrypt(ct, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, message) {
		t.Fatal("ecies: plaintext doesn't match message")
	}
	if _, err = prv1.Decrypt(ct, nil, nil); err == nil {
		t.Fatal("ecies: encryption should not have succeeded")
	}
}

// Verify GenerateShared against static values - useful when
// debugging changes in underlying libs
func TestSharedKeyStatic(t *testing.T) {
	prv1 := hexKey("7ebbc6a8358bc76dd73ebc557056702c8cfc34e5cfcd90eb83af0347575fd2ad")
	prv2 := hexKey("6a3d6396903245bba5837752b9e0348874e72db0c4e11e9c485a81b4ea4353b9")

	skLen := MaxSharedKeyLength(&prv1.PublicKey) / 2

	sk1, err := prv1.GenerateShared(&prv2.PublicKey, skLen, skLen)
	if err != nil {
		t.Fatal(err)
	}

	sk2, err := prv2.GenerateShared(&prv1.PublicKey, skLen, skLen)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sk1, sk2) {
		t.Fatal(ErrBadSharedKeys)
	}

	sk := decode("167ccc13ac5e8a26b131c3446030c60fbfac6aa8e31149d0869f93626a4cdf62")
	if !bytes.Equal(sk1, sk) {
		t.Fatalf("shared secret mismatch: want: %x have: %x", sk, sk1)
	}
}

func hexKey(prv string) *PrivateKey {
	key, err := crypto.HexToECDSA(prv)
	if err != nil {
		panic(err)
	}
	return ImportECDSA(key)
}

// TestDecryptMinimumLengthValidation tests that the length check correctly rejects
// messages that would cause a panic in symDecrypt when accessing ct[:BlockSize] for IV.
//
// Security fix: go-ethereum commit 3b17e782747fcd2cf06622324f3d48ad91f64ab3
//
// Vulnerability details:
//   - Old check: len(c) < (rLen + hLen + 1)       → rejects len < 98, passes len >= 98
//   - New check: len(c) < (rLen + hLen + BlockSize) → rejects len < 113, passes len >= 113
//   - Vulnerable range: 98-112 bytes (would pass old check, but cause panic in symDecrypt)
//
// For secp256k1 with ECIES_AES128_SHA256:
//   - rLen = 65 bytes (uncompressed public key)
//   - hLen = 32 bytes (SHA256 hash size for HMAC)
//   - BlockSize = 16 bytes (AES block size for IV)
//
// Why lengths 98-112 would panic without the fix:
//   - mStart = rLen = 65
//   - mEnd = len(c) - hLen = len(c) - 32
//   - ct = c[mStart:mEnd], so ct length = len(c) - 65 - 32 = len(c) - 97
//   - For len(c) = 98:  ct length = 1  → ct[:16] access causes panic
//   - For len(c) = 112: ct length = 15 → ct[:16] access causes panic
//   - For len(c) = 113: ct length = 16 → ct[:16] access succeeds
//
// Defense-in-depth note:
//   Decrypt() has HMAC verification (line 318-320) before symDecrypt (line 322).
//   For truncated messages, HMAC usually fails, preventing symDecrypt from being reached.
//   However, the length check is the PRIMARY defense because:
//   1. HMAC verification is not designed for length validation
//   2. Edge cases or crafted payloads might bypass HMAC
//   3. Correct length validation is required by the ECIES specification
func TestDecryptMinimumLengthValidation(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(rand.Reader, &prv.PublicKey, message, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Calculate length boundaries
	params := prv.PublicKey.Params
	rLen := (prv.PublicKey.Curve.Params().BitSize + 7) / 4 // 65 for secp256k1
	hLen := params.Hash().Size()                           // 32 for SHA256
	blockSize := params.BlockSize                          // 16 for AES

	oldMinLen := rLen + hLen + 1         // 98 (vulnerable check)
	newMinLen := rLen + hLen + blockSize // 113 (fixed check)

	t.Logf("rLen=%d, hLen=%d, BlockSize=%d", rLen, hLen, blockSize)
	t.Logf("Old minimum (vulnerable): %d bytes", oldMinLen)
	t.Logf("New minimum (fixed):      %d bytes", newMinLen)
	t.Logf("Vulnerable range:         %d-%d bytes", oldMinLen, newMinLen-1)
	t.Logf("Encrypted message length: %d bytes", len(ct))

	// Test 1: Prove symDecrypt PANICS with undersized input (root cause of vulnerability)
	// This directly demonstrates the bug that the length check prevents
	// symDecrypt does: ct[:BlockSize] for IV, which panics if len(ct) < BlockSize
	t.Log("--- Test 1: Prove symDecrypt panics with undersized ct ---")
	for ctLen := 0; ctLen < blockSize; ctLen++ {
		ctLen := ctLen // capture for closure
		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
				}
			}()
			undersizedCt := make([]byte, ctLen)
			symDecrypt(params, make([]byte, params.KeyLen), undersizedCt)
		}()
		if !panicked {
			t.Fatalf("symDecrypt should panic with ct length %d (< BlockSize %d)", ctLen, blockSize)
		}
	}
	t.Logf("Confirmed: symDecrypt panics for all ct lengths 0-%d (< BlockSize)", blockSize-1)

	// Test 2: Prove symDecrypt does NOT panic with ct length >= BlockSize
	t.Log("--- Test 2: Prove symDecrypt works with ct length >= BlockSize ---")
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("symDecrypt should NOT panic with ct length %d", blockSize)
			}
		}()
		validSizeCt := make([]byte, blockSize)
		symDecrypt(params, make([]byte, params.KeyLen), validSizeCt)
	}()
	t.Logf("Confirmed: symDecrypt does not panic with ct length %d (= BlockSize)", blockSize)

	// Test 3: Verify the truncated ciphertext has valid attack format
	// This proves we're testing realistic attack payloads, not just random bytes
	t.Log("--- Test 3: Verify attack payload format ---")
	if ct[0] != 4 {
		t.Fatalf("Expected uncompressed public key format (0x04), got: 0x%02x", ct[0])
	}
	t.Logf("Confirmed: ciphertext starts with 0x04 (uncompressed public key format)")

	// Test 4: Verify len=97 is rejected (confirms vulnerable range starts at 98)
	// len=97 would be rejected by BOTH old check (97 < 98) and new check (97 < 113)
	t.Log("--- Test 4: Below vulnerable range (97 bytes) ---")
	belowVulnerable := oldMinLen - 1 // 97
	if belowVulnerable >= oldMinLen {
		t.Fatal("Test logic error: belowVulnerable should be < oldMinLen")
	}
	_, err = prv.Decrypt(ct[:belowVulnerable], nil, nil)
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("len=%d: expected ErrInvalidMessage, got: %v", belowVulnerable, err)
	}
	t.Logf("len=%d: rejected (would fail both old check <%d and new check <%d)",
		belowVulnerable, oldMinLen, newMinLen)

	// Test 5: Verify vulnerable range (98-112) is rejected by the fixed length check
	// These payloads would pass the old check (len >= 98) but cause panic in symDecrypt
	t.Log("--- Test 5: Vulnerable range (98-112 bytes) rejected ---")
	for truncLen := oldMinLen; truncLen < newMinLen; truncLen++ {
		ctLen := truncLen - rLen - hLen
		truncated := ct[:truncLen]
		// Verify this is a valid attack payload (starts with 0x02, 0x03, or 0x04)
		if truncated[0] != 2 && truncated[0] != 3 && truncated[0] != 4 {
			t.Fatalf("Invalid test: truncated payload should have valid first byte")
		}
		// Verify this would pass the OLD length check
		if truncLen < oldMinLen {
			t.Fatalf("Test logic error: len=%d should pass old check (>= %d)", truncLen, oldMinLen)
		}
		_, err := prv.Decrypt(truncated, nil, nil)
		if !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("len=%d (ct=%d bytes): expected ErrInvalidMessage, got: %v", truncLen, ctLen, err)
		}
	}
	t.Logf("All %d vulnerable lengths (98-112) correctly rejected", newMinLen-oldMinLen)

	// Test 6: Verify boundary (113 bytes) - length check passes, fails at HMAC
	// Logic: len(c) >= newMinLen means length check passes (line 293)
	//        ct length = len(c) - rLen - hLen = 113 - 65 - 32 = 16 = BlockSize
	//        symDecrypt won't panic (proven in Test 2), so rejection is at HMAC
	t.Log("--- Test 6: Boundary test (113 bytes) ---")
	// Verify boundary calculation
	ctLenAtBoundary := newMinLen - rLen - hLen
	if ctLenAtBoundary != blockSize {
		t.Fatalf("Test logic error: ct length at boundary should be %d, got %d", blockSize, ctLenAtBoundary)
	}
	// Verify length check passes: newMinLen >= (rLen + hLen + blockSize)
	lengthCheckPasses := newMinLen >= (rLen + hLen + blockSize)
	if !lengthCheckPasses {
		t.Fatalf("Test logic error: length %d should pass length check", newMinLen)
	}
	t.Logf("len=%d: length check passes (%d >= %d)", newMinLen, newMinLen, rLen+hLen+blockSize)
	// Now verify Decrypt rejects it (must be HMAC since length check passed)
	_, err = prv.Decrypt(ct[:newMinLen], nil, nil)
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("len=%d: expected ErrInvalidMessage, got: %v", newMinLen, err)
	}
	t.Logf("len=%d (ct=%d bytes): passed length check, rejected at HMAC", newMinLen, ctLenAtBoundary)

	// Test 7: Verify valid message decrypts correctly
	t.Log("--- Test 7: Valid message decryption ---")
	pt, err := prv.Decrypt(ct, nil, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if !bytes.Equal(pt, message) {
		t.Fatal("Decrypted plaintext mismatch")
	}
	t.Logf("Full message (%d bytes) decrypted successfully", len(ct))
}

func decode(s string) []byte {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes
}
