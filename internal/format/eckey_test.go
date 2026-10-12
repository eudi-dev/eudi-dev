// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package format

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// The signing, JWK and thumbprint code reads EC key coordinates through these
// helpers. Their output must equal the SEC1 point and the fixed-width JWK
// coordinates on P-256, P-384 and P-521. The big.Int fields serve as an
// independent reference.

func referenceCoords(pub *ecdsa.PublicKey) (x, y []byte) {
	size := (pub.Curve.Params().BitSize + 7) / 8
	return pub.X.FillBytes(make([]byte, size)), //nolint:staticcheck // the independent reference for the helper
		pub.Y.FillBytes(make([]byte, size)) //nolint:staticcheck // the independent reference for the helper
}

func TestECPublicCoords_MatchesFieldAccess(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}
	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			size := (c.curve.Params().BitSize + 7) / 8
			// 500 keys include coordinates with a leading zero byte. big.Int.Bytes() omits that byte.
			for i := 0; i < 500; i++ {
				key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				gotX, gotY, err := ECPublicCoords(&key.PublicKey)
				if err != nil {
					t.Fatalf("ECPublicCoords: %v", err)
				}
				if len(gotX) != size || len(gotY) != size {
					t.Fatalf("coordinate width = %d/%d, want %d", len(gotX), len(gotY), size)
				}
				wantX, wantY := referenceCoords(&key.PublicKey)
				if !bytes.Equal(gotX, wantX) || !bytes.Equal(gotY, wantY) {
					t.Fatalf("coordinates differ from field access:\n got x=%x y=%x\nwant x=%x y=%x", gotX, gotY, wantX, wantY)
				}
				// The SEC1 uncompressed point is a second independent reference.
				marshaled := elliptic.Marshal(c.curve, key.X, key.Y) //nolint:staticcheck // the independent reference for the helper
				if !bytes.Equal(append([]byte{4}, append(gotX, gotY...)...), marshaled) {
					t.Fatalf("coordinates do not reassemble into the SEC1 point")
				}
			}
		})
	}
}

func TestECPublicKeyFromCoords_RoundTrip(t *testing.T) {
	for i := 0; i < 500; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		x, y, err := ECPublicCoords(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ECPublicKeyFromCoords(elliptic.P256(), x, y)
		if err != nil {
			t.Fatalf("ECPublicKeyFromCoords: %v", err)
		}
		if !got.Equal(&key.PublicKey) {
			t.Fatal("round-tripped key differs from the original")
		}
	}
}

func TestECPublicKeyFromCoords_AcceptsShortCoordinates(t *testing.T) {
	// A JWK may drop a leading zero byte. The short coordinate must still rebuild the key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y, err := ECPublicCoords(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ECPublicKeyFromCoords(elliptic.P256(), bytes.TrimLeft(x, "\x00"), bytes.TrimLeft(y, "\x00"))
	if err != nil {
		t.Fatalf("short coordinates were rejected: %v", err)
	}
	if !got.Equal(&key.PublicKey) {
		t.Fatal("key rebuilt from short coordinates differs")
	}
}

func TestECPublicKeyFromCoords_RejectsOffCurve(t *testing.T) {
	// A point outside the curve must be refused.
	x := make([]byte, 32)
	y := make([]byte, 32)
	x[31] = 1
	y[31] = 2
	if _, err := ECPublicKeyFromCoords(elliptic.P256(), x, y); err == nil {
		t.Fatal("an off-curve point was accepted")
	}
}

func TestECPublicKeyFromCoords_RejectsOverlongCoordinate(t *testing.T) {
	if _, err := ECPublicKeyFromCoords(elliptic.P256(), make([]byte, 33), make([]byte, 32)); err == nil {
		t.Fatal("an over-long coordinate was accepted")
	}
}

func TestPrivateKeyScalar_MatchesFieldAccess(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		size := (curve.Params().BitSize + 7) / 8
		for i := 0; i < 300; i++ {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			got, err := key.Bytes()
			if err != nil {
				t.Fatalf("PrivateKey.Bytes: %v", err)
			}
			want := key.D.FillBytes(make([]byte, size)) //nolint:staticcheck // the independent reference for the helper
			if !bytes.Equal(got, want) {
				t.Fatalf("private scalar differs from field access:\n got %x\nwant %x", got, want)
			}
			back, err := ecdsa.ParseRawPrivateKey(curve, got)
			if err != nil || !back.Equal(key) {
				t.Fatalf("private scalar did not round-trip: %v", err)
			}
		}
	}
}
