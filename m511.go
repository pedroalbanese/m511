// SPDX-License-Identifier: ISC
//
// Copyright (c) 2026 Pedro F. Albanese
//
// Package m511 implementa ECDH sobre a curva de Montgomery M-511,
// com API compatível com o pacote e521 do EDGETk.
//
// Referência:
//   - Diego F. Aranha, Paulo S. L. M. Barreto, Geovandro C. C. F. Pereira,
//     Jefferson Ricardini, "A note on high-security general-purpose
//     elliptic curves", 2013. https://eprint.iacr.org/2013/647
//   - https://std.neuromancer.sk/other/M-511
//   - RFC 7748 (Curve25519/Curve448) — modelo para a escada de Montgomery
//
// AVISO DE SEGURANÇA:
//
//   Esta implementação usa math/big para a aritmética de campo, que NÃO é
//   constant-time. Ela é vulnerável a ataques de temporização (timing
//   attacks) e de canal lateral. NÃO use em produção sem antes substituir
//   a aritmética de campo por uma implementação constant-time.
package m511

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
)

// -----------------------------------------------------------------------------
// Parâmetros
// -----------------------------------------------------------------------------

var (
	pHex = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF45"
	aHex = "081806"
	orderHex = "100000000000000000000000000000000000000000000000000000000000000017B5FEFF30C7F5677AB2AEEBD13779A2AC125042A6AA10BFA54C15BAB76BAF1B"
	cofactorHex = "08"
	generatorXHex = "05"

	pBig, _          = new(big.Int).SetString(pHex, 16)
	aBig, _          = new(big.Int).SetString(aHex, 16)
	orderBig, _      = new(big.Int).SetString(orderHex, 16)
	cofactorBig, _   = new(big.Int).SetString(cofactorHex, 16)
	generatorXBig, _ = new(big.Int).SetString(generatorXHex, 16)
)

type Curve struct {
	Name     string
	P        *big.Int
	A        *big.Int
	Order    *big.Int
	Cofactor *big.Int
	Gx       *big.Int
	BitSize  int
}

var (
	initOnce sync.Once
	curve    *Curve
)

func initCurve() {
	curve = &Curve{
		Name:     "M-511",
		P:        new(big.Int).Set(pBig),
		A:        new(big.Int).Set(aBig),
		Order:    new(big.Int).Set(orderBig),
		Cofactor: new(big.Int).Set(cofactorBig),
		Gx:       new(big.Int).Set(generatorXBig),
		BitSize:  511,
	}
}

func M511() *Curve {
	initOnce.Do(initCurve)
	return curve
}

// Params retorna os parâmetros no formato elliptic.CurveParams.
func (curve *Curve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       new(big.Int).Set(curve.P),
		N:       new(big.Int).Set(curve.Order),
		B:       big.NewInt(1),
		Gx:      new(big.Int).Set(curve.Gx),
		Gy:      big.NewInt(0),
		BitSize: curve.BitSize,
		Name:    curve.Name,
	}
}

// -----------------------------------------------------------------------------
// Tipos
// -----------------------------------------------------------------------------

type Point struct {
	X, Y *big.Int
}

type PublicKey struct {
	Point
	Curve *Curve
}

type PrivateKey struct {
	D     *big.Int
	Curve *Curve
}

// -----------------------------------------------------------------------------
// Geração de chaves
// -----------------------------------------------------------------------------

func GenerateKey() (*PrivateKey, *PublicKey, error) {
	return GenerateKeyWithReader(rand.Reader)
}

func GenerateKeyWithReader(reader io.Reader) (*PrivateKey, *PublicKey, error) {
	if reader == nil {
		reader = rand.Reader
	}
	curve := M511()
	max := new(big.Int).Sub(curve.Order, big.NewInt(1))
	d, err := rand.Int(reader, max)
	if err != nil {
		return nil, nil, err
	}
	d.Add(d, big.NewInt(1))
	priv := &PrivateKey{D: d, Curve: curve}
	pub := priv.Public()
	return priv, pub, nil
}

func (priv *PrivateKey) Public() *PublicKey {
	curve := priv.Curve
	if curve == nil {
		curve = M511()
		priv.Curve = curve
	}
	x := new(big.Int).Set(curve.Gx)
	pubX := montgomeryLadder(curve, x, priv.D)
	pubY := curve.recoverY(pubX)
	return &PublicKey{
		Point: Point{X: pubX, Y: pubY},
		Curve: curve,
	}
}

func (priv *PrivateKey) GetPublic() *PublicKey {
	return priv.Public()
}

// NewPublicKey cria uma nova chave pública a partir de coordenadas.
func NewPublicKey(x, y *big.Int) *PublicKey {
	return &PublicKey{
		Point: Point{X: x, Y: y},
		Curve: M511(),
	}
}

// -----------------------------------------------------------------------------
// ECDH
// -----------------------------------------------------------------------------

func (priv *PrivateKey) ECDH(pub *PublicKey) ([]byte, error) {
	if pub == nil || pub.X == nil {
		return nil, errors.New("m511: chave pública inválida")
	}
	curve := priv.Curve
	if curve == nil {
		curve = M511()
		priv.Curve = curve
	}
	if pub.X.Sign() < 0 || pub.X.Cmp(curve.P) >= 0 {
		return nil, errors.New("m511: coordenada x fora do corpo")
	}
	if !curve.IsOnCurve(pub.X) {
		return nil, errors.New("m511: ponto não está na curva")
	}
	shared := montgomeryLadder(curve, pub.X, priv.D)
	if shared.Sign() == 0 {
		return nil, errors.New("m511: segredo compartilhado é o ponto no infinito")
	}
	return bigToFixedBytes(shared, 64), nil
}

// -----------------------------------------------------------------------------
// Validação e recuperação de Y
// -----------------------------------------------------------------------------

func (curve *Curve) IsOnCurve(x *big.Int) bool {
	if x.Sign() < 0 || x.Cmp(curve.P) >= 0 {
		return false
	}
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	t := new(big.Int).Mul(x, x)
	t.Mul(t, curve.A)
	rhs.Add(rhs, t)
	rhs.Add(rhs, x)
	rhs.Mod(rhs, curve.P)
	if rhs.Sign() == 0 {
		return true
	}
	exp := new(big.Int).Sub(curve.P, big.NewInt(1))
	exp.Rsh(exp, 1)
	leg := new(big.Int).Exp(rhs, exp, curve.P)
	return leg.Cmp(big.NewInt(1)) == 0
}

func (curve *Curve) IsInSubgroup(x *big.Int) bool {
	if !curve.IsOnCurve(x) {
		return false
	}
	fullOrder := new(big.Int).Mul(curve.Order, curve.Cofactor)
	orderQ := montgomeryLadder(curve, x, fullOrder)
	return orderQ.Sign() == 0
}

func (curve *Curve) recoverY(x *big.Int) *big.Int {
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	t := new(big.Int).Mul(x, x)
	t.Mul(t, curve.A)
	rhs.Add(rhs, t)
	rhs.Add(rhs, x)
	rhs.Mod(rhs, curve.P)
	y := new(big.Int).ModSqrt(rhs, curve.P)
	if y == nil {
		return nil
	}
	if y.Bit(0) == 1 {
		y.Sub(curve.P, y)
	}
	return y
}

// CompressPoint comprime um ponto em 64 bytes (apenas X).
func (curve *Curve) CompressPoint(x, y *big.Int) []byte {
	return bigToFixedBytes(x, 64)
}

// DecompressPoint descomprime 64 bytes em (x, y).
func (curve *Curve) DecompressPoint(data []byte) (*big.Int, *big.Int) {
	if len(data) != 64 {
		return nil, nil
	}
	x := new(big.Int).SetBytes(data)
	if x.Cmp(curve.P) >= 0 {
		return nil, nil
	}
	if !curve.IsOnCurve(x) {
		return nil, nil
	}
	y := curve.recoverY(x)
	if y == nil {
		return nil, nil
	}
	return x, y
}

// -----------------------------------------------------------------------------
// Escada de Montgomery
// -----------------------------------------------------------------------------

func montgomeryLadder(curve *Curve, x *big.Int, k *big.Int) *big.Int {
	if k.Sign() == 0 {
		return big.NewInt(0)
	}
	p := curve.P
	a := curve.A

	// a24 = (A - 2) / 4  (RFC 7748)
	a24 := new(big.Int).Sub(a, big.NewInt(2))
	a24.Mul(a24, new(big.Int).ModInverse(big.NewInt(4), p))
	a24.Mod(a24, p)

	x1 := new(big.Int).Set(x)
	x2 := big.NewInt(1)
	z2 := big.NewInt(0)
	x3 := new(big.Int).Set(x)
	z3 := big.NewInt(1)
	swap := uint(0)

	for t := k.BitLen() - 1; t >= 0; t-- {
		kt := uint(k.Bit(t))
		if swap != kt {
			x2, x3 = x3, x2
			z2, z3 = z3, z2
		}
		swap = kt

		A_ := new(big.Int).Add(x2, z2)
		A_.Mod(A_, p)
		AA := new(big.Int).Mul(A_, A_)
		AA.Mod(AA, p)
		B_ := new(big.Int).Sub(x2, z2)
		B_.Mod(B_, p)
		BB := new(big.Int).Mul(B_, B_)
		BB.Mod(BB, p)
		E := new(big.Int).Sub(AA, BB)
		E.Mod(E, p)
		C_ := new(big.Int).Add(x3, z3)
		C_.Mod(C_, p)
		D_ := new(big.Int).Sub(x3, z3)
		D_.Mod(D_, p)
		DA := new(big.Int).Mul(D_, A_)
		DA.Mod(DA, p)
		CB := new(big.Int).Mul(C_, B_)
		CB.Mod(CB, p)

		t1 := new(big.Int).Add(DA, CB)
		t1.Mod(t1, p)
		x3 = new(big.Int).Mul(t1, t1)
		x3.Mod(x3, p)

		t2 := new(big.Int).Sub(DA, CB)
		t2.Mod(t2, p)
		t2.Mul(t2, t2)
		t2.Mod(t2, p)
		z3 = new(big.Int).Mul(x1, t2)
		z3.Mod(z3, p)

		x2 = new(big.Int).Mul(AA, BB)
		x2.Mod(x2, p)

		t3 := new(big.Int).Mul(a24, E)
		t3.Mod(t3, p)
		t3.Add(t3, AA)
		t3.Mod(t3, p)
		z2 = new(big.Int).Mul(E, t3)
		z2.Mod(z2, p)
	}

	if swap == 1 {
		x2, x3 = x3, x2
		z2, z3 = z3, z2
	}

	if z2.Sign() == 0 {
		return big.NewInt(0)
	}
	z2Inv := new(big.Int).ModInverse(z2, p)
	result := new(big.Int).Mul(x2, z2Inv)
	result.Mod(result, p)
	return result
}

// -----------------------------------------------------------------------------
// Serialização simples (64 bytes)
// -----------------------------------------------------------------------------

func (pub *PublicKey) Marshal() []byte {
	return bigToFixedBytes(pub.X, 64)
}

func UnmarshalPublicKey(data []byte) (*PublicKey, error) {
	if len(data) != 64 {
		return nil, errors.New("m511: tamanho inválido")
	}
	curve := M511()
	x := new(big.Int).SetBytes(data)
	if x.Cmp(curve.P) >= 0 {
		return nil, errors.New("m511: coordenada x fora do corpo")
	}
	y := curve.recoverY(x)
	return &PublicKey{Point: Point{X: x, Y: y}, Curve: curve}, nil
}

func (priv *PrivateKey) MarshalPrivateKey() []byte {
	return bigToFixedBytes(priv.D, 64)
}

func UnmarshalPrivateKey(data []byte) (*PrivateKey, error) {
	if len(data) != 64 {
		return nil, errors.New("m511: tamanho inválido")
	}
	curve := M511()
	d := new(big.Int).SetBytes(data)
	if d.Sign() == 0 || d.Cmp(curve.Order) >= 0 {
		return nil, errors.New("m511: escalar privado fora do intervalo")
	}
	return &PrivateKey{D: d, Curve: curve}, nil
}

func (pub *PublicKey) Hex() string {
	return hex.EncodeToString(pub.Marshal())
}

func (pub *PublicKey) Equal(other *PublicKey) bool {
	if pub == nil || other == nil || pub.X == nil || other.X == nil {
		return false
	}
	return pub.X.Cmp(other.X) == 0
}

// -----------------------------------------------------------------------------
// PKCS#8 e PKIX
// -----------------------------------------------------------------------------

var oidM511 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}

type pkAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkcs8PrivateKey struct {
	Version             int
	PrivateKeyAlgorithm pkAlgorithmIdentifier
	PrivateKey          []byte
}

type pkixPublicKey struct {
	Algorithm        pkAlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func (priv *PrivateKey) MarshalPKCS8PrivateKey() ([]byte, error) {
	curve := priv.Curve
	if curve == nil {
		curve = M511()
		priv.Curve = curve
	}
	if priv.D.Sign() <= 0 || priv.D.Cmp(curve.Order) >= 0 {
		return nil, errors.New("m511: escalar privado fora do intervalo")
	}
	dBytes := bigToFixedBytes(priv.D, 64)
	info := pkcs8PrivateKey{
		Version: 0,
		PrivateKeyAlgorithm: pkAlgorithmIdentifier{
			Algorithm:  oidM511,
			Parameters: asn1.RawValue{Tag: asn1.TagOID},
		},
		PrivateKey: dBytes,
	}
	return asn1.Marshal(info)
}

func ParsePKCS8PrivateKey(der []byte) (*PrivateKey, error) {
	var info pkcs8PrivateKey
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("m511: falha ao parsear PKCS#8: %w", err)
	}
	if !info.PrivateKeyAlgorithm.Algorithm.Equal(oidM511) {
		return nil, errors.New("m511: OID inválido em PKCS#8")
	}
	if len(info.PrivateKey) != 64 {
		return nil, fmt.Errorf("m511: tamanho inválido: %d", len(info.PrivateKey))
	}
	curve := M511()
	d := new(big.Int).SetBytes(info.PrivateKey)
	if d.Sign() == 0 || d.Cmp(curve.Order) >= 0 {
		return nil, errors.New("m511: escalar privado fora do intervalo")
	}
	return &PrivateKey{D: d, Curve: curve}, nil
}

// ParsePrivateKey é um alias para ParsePKCS8PrivateKey.
func ParsePrivateKey(der []byte) (*PrivateKey, error) {
	return ParsePKCS8PrivateKey(der)
}

func (pub *PublicKey) MarshalPKIXPublicKey() ([]byte, error) {
	curve := pub.Curve
	if curve == nil {
		curve = M511()
		pub.Curve = curve
	}
	if pub.X == nil {
		return nil, errors.New("m511: chave pública nula")
	}
	if pub.X.Sign() < 0 || pub.X.Cmp(curve.P) >= 0 {
		return nil, errors.New("m511: coordenada X fora do corpo")
	}
	if !curve.IsOnCurve(pub.X) {
		return nil, errors.New("m511: ponto não está na curva")
	}
	xBytes := bigToFixedBytes(pub.X, 64)
	info := pkixPublicKey{
		Algorithm: pkAlgorithmIdentifier{
			Algorithm:  oidM511,
			Parameters: asn1.RawValue{Tag: asn1.TagOID},
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     xBytes,
			BitLength: len(xBytes) * 8,
		},
	}
	return asn1.Marshal(info)
}

// MarshalPKCS8PublicKey é um alias para MarshalPKIXPublicKey.
func (pub *PublicKey) MarshalPKCS8PublicKey() ([]byte, error) {
	return pub.MarshalPKIXPublicKey()
}

func ParsePKIXPublicKey(der []byte) (*PublicKey, error) {
	var info pkixPublicKey
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("m511: falha ao parsear PKIX: %w", err)
	}
	if !info.Algorithm.Algorithm.Equal(oidM511) {
		return nil, errors.New("m511: OID inválido em PKIX")
	}
	if len(info.SubjectPublicKey.Bytes) != 64 {
		return nil, fmt.Errorf("m511: tamanho inválido: %d", len(info.SubjectPublicKey.Bytes))
	}
	curve := M511()
	x := new(big.Int).SetBytes(info.SubjectPublicKey.Bytes)
	if x.Cmp(curve.P) >= 0 {
		return nil, errors.New("m511: coordenada X fora do corpo")
	}
	if !curve.IsOnCurve(x) {
		return nil, errors.New("m511: ponto não está na curva")
	}
	y := curve.recoverY(x)
	return &PublicKey{Point: Point{X: x, Y: y}, Curve: curve}, nil
}

// -----------------------------------------------------------------------------
// Utilidades
// -----------------------------------------------------------------------------

func bigToFixedBytes(x *big.Int, size int) []byte {
	b := x.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func HexPrefix(x *big.Int, n int) string {
	s := x.Text(16)
	if len(s) < n {
		return fmt.Sprintf("%0*s", n, s)
	}
	return s[:n]
}

func MontgomeryLadder(curve *Curve, x *big.Int, k *big.Int) *big.Int {
	return montgomeryLadder(curve, x, k)
}
