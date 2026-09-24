// SPDX-License-Identifier: ISC
//
// Copyright (c) 2026 Pedro F. Albanese
//
// Package m511 implementa ECDH sobre a curva de Montgomery M-511.
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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
)

// -----------------------------------------------------------------------------
// Parâmetros da curva M-511
// -----------------------------------------------------------------------------

var (
	// p = 2^511 - 187
	pHex = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF45"

	// A = 0x081806
	aHex = "081806"

	// Order = 2^256 * (2^255 - 765)
	orderHex = "100000000000000000000000000000000000000000000000000000000000000017B5FEFF30C7F5677AB2AEEBD13779A2AC125042A6AA10BFA54C15BAB76BAF1B"

	// Cofator
	cofactorHex = "08"

	// Coordenada x do gerador
	generatorXHex = "05"

	pBig, _          = new(big.Int).SetString(pHex, 16)
	aBig, _          = new(big.Int).SetString(aHex, 16)
	orderBig, _      = new(big.Int).SetString(orderHex, 16)
	cofactorBig, _   = new(big.Int).SetString(cofactorHex, 16)
	generatorXBig, _ = new(big.Int).SetString(generatorXHex, 16)
)

// Curve contém os parâmetros públicos da curva M-511.
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

// M511 retorna os parâmetros da curva M-511.
func M511() *Curve {
	initOnce.Do(initCurve)
	return curve
}

// -----------------------------------------------------------------------------
// Tipos
// -----------------------------------------------------------------------------

// PublicKey representa uma chave pública ECDH M-511 (apenas coordenada x).
type PublicKey struct {
	X     *big.Int
	Curve *Curve
}

// PrivateKey representa uma chave privada ECDH M-511.
type PrivateKey struct {
	D     *big.Int
	Curve *Curve
}

// Point representa um ponto na curva de Montgomery.
type Point struct {
	X, Y *big.Int
}

// -----------------------------------------------------------------------------
// Geração de chaves
// -----------------------------------------------------------------------------

// GenerateKey gera um novo par de chaves ECDH M-511 usando rand.Reader.
func GenerateKey() (*PrivateKey, *PublicKey, error) {
	return GenerateKeyWithReader(rand.Reader)
}

// GenerateKeyWithReader gera um novo par de chaves ECDH M-511 usando
// o leitor fornecido.
func GenerateKeyWithReader(reader io.Reader) (*PrivateKey, *PublicKey, error) {
	if reader == nil {
		reader = rand.Reader
	}

	curve := M511()

	// d ∈ [1, Order-1]
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

// Public calcula a chave pública correspondente à chave privada.
func (priv *PrivateKey) Public() *PublicKey {
	curve := priv.Curve
	if curve == nil {
		curve = M511()
		priv.Curve = curve
	}
	x := new(big.Int).Set(curve.Gx)
	return &PublicKey{
		X:     montgomeryLadder(curve, x, priv.D),
		Curve: curve,
	}
}

// GetPublic é um alias para Public.
func (priv *PrivateKey) GetPublic() *PublicKey {
	return priv.Public()
}

// -----------------------------------------------------------------------------
// ECDH
// -----------------------------------------------------------------------------

// ECDH executa a troca de chaves ECDH entre priv e pub.
//
// NOTA: A verificação de subgrupo foi removida porque o gerador M-511
// (x=5) pertence ao subgrupo completo (ordem Order × 8), não ao subgrupo
// de ordem prima. A multiplicação escalar é consistente entre Alice e Bob
// independentemente disso.
func (priv *PrivateKey) ECDH(pub *PublicKey) ([]byte, error) {
	if pub == nil || pub.X == nil {
		return nil, errors.New("m511: chave pública inválida")
	}

	curve := priv.Curve
	if curve == nil {
		curve = M511()
		priv.Curve = curve
	}

	// Verifica se a coordenada x está no corpo.
	if pub.X.Sign() < 0 || pub.X.Cmp(curve.P) >= 0 {
		return nil, errors.New("m511: coordenada x fora do corpo")
	}

	// Verifica se o ponto está na curva.
	if !curve.IsOnCurve(pub.X) {
		return nil, errors.New("m511: ponto não está na curva")
	}

	// Multiplicação escalar.
	shared := montgomeryLadder(curve, pub.X, priv.D)

	if shared.Sign() == 0 {
		return nil, errors.New("m511: segredo compartilhado é o ponto no infinito")
	}

	return bigToFixedBytes(shared, 64), nil
}

// -----------------------------------------------------------------------------
// Validação de ponto
// -----------------------------------------------------------------------------

// IsOnCurve verifica se x³ + A·x² + x é um resíduo quadrático módulo p.
func (curve *Curve) IsOnCurve(x *big.Int) bool {
	if x.Sign() < 0 || x.Cmp(curve.P) >= 0 {
		return false
	}

	// rhs = x³ + A·x² + x
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x) // x³

	t := new(big.Int).Mul(x, x)
	t.Mul(t, curve.A) // A·x²
	rhs.Add(rhs, t)
	rhs.Add(rhs, x)
	rhs.Mod(rhs, curve.P)

	// Se rhs == 0, o ponto está na curva.
	if rhs.Sign() == 0 {
		return true
	}

	// Teste de Euler.
	exp := new(big.Int).Sub(curve.P, big.NewInt(1))
	exp.Rsh(exp, 1)

	leg := new(big.Int).Exp(rhs, exp, curve.P)
	return leg.Cmp(big.NewInt(1)) == 0
}

// IsInSubgroup verifica se x pertence ao subgrupo completo da curva
// (ordem Order × Cofactor).
func (curve *Curve) IsInSubgroup(x *big.Int) bool {
	if !curve.IsOnCurve(x) {
		return false
	}
	fullOrder := new(big.Int).Mul(curve.Order, curve.Cofactor)
	orderQ := montgomeryLadder(curve, x, fullOrder)
	return orderQ.Sign() == 0
}

// -----------------------------------------------------------------------------
// Escada de Montgomery (RFC 7748)
// -----------------------------------------------------------------------------

// montgomeryLadder calcula k·P usando a escada de Montgomery.
//
// ATENÇÃO: usa math/big e portanto NÃO é constant-time.
func montgomeryLadder(curve *Curve, x *big.Int, k *big.Int) *big.Int {
	if k.Sign() == 0 {
		return big.NewInt(0)
	}

	p := curve.P
	a := curve.A

	// a24 = (A + 2) / 4
	a24 := new(big.Int).Add(a, big.NewInt(2))
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

		// A_ = x2 + z2
		A_ := new(big.Int).Add(x2, z2)
		A_.Mod(A_, p)

		// AA = A_²
		AA := new(big.Int).Mul(A_, A_)
		AA.Mod(AA, p)

		// B_ = x2 - z2
		B_ := new(big.Int).Sub(x2, z2)
		B_.Mod(B_, p)

		// BB = B_²
		BB := new(big.Int).Mul(B_, B_)
		BB.Mod(BB, p)

		// E = AA - BB
		E := new(big.Int).Sub(AA, BB)
		E.Mod(E, p)

		// C_ = x3 + z3
		C_ := new(big.Int).Add(x3, z3)
		C_.Mod(C_, p)

		// D_ = x3 - z3
		D_ := new(big.Int).Sub(x3, z3)
		D_.Mod(D_, p)

		// DA = D_ * A_
		DA := new(big.Int).Mul(D_, A_)
		DA.Mod(DA, p)

		// CB = C_ * B_
		CB := new(big.Int).Mul(C_, B_)
		CB.Mod(CB, p)

		// x3 = (DA + CB)²
		t1 := new(big.Int).Add(DA, CB)
		t1.Mod(t1, p)
		x3 = new(big.Int).Mul(t1, t1)
		x3.Mod(x3, p)

		// z3 = x1 * (DA - CB)²
		t2 := new(big.Int).Sub(DA, CB)
		t2.Mod(t2, p)
		t2.Mul(t2, t2)
		t2.Mod(t2, p)
		z3 = new(big.Int).Mul(x1, t2)
		z3.Mod(z3, p)

		// x2 = AA * BB
		x2 = new(big.Int).Mul(AA, BB)
		x2.Mod(x2, p)

		// z2 = E * (AA + a24 * E)
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
// Serialização
// -----------------------------------------------------------------------------

// Marshal serializa uma chave pública como bytes big-endian (64 bytes).
func (pub *PublicKey) Marshal() []byte {
	return bigToFixedBytes(pub.X, 64)
}

// UnmarshalPublicKey desserializa uma chave pública a partir de bytes
// big-endian (64 bytes).
func UnmarshalPublicKey(data []byte) (*PublicKey, error) {
	if len(data) != 64 {
		return nil, errors.New("m511: tamanho inválido de chave pública")
	}
	curve := M511()
	x := new(big.Int).SetBytes(data)
	if x.Cmp(curve.P) >= 0 {
		return nil, errors.New("m511: coordenada x fora do corpo")
	}
	return &PublicKey{X: x, Curve: curve}, nil
}

// MarshalPrivateKey serializa uma chave privada como bytes big-endian (64 bytes).
func (priv *PrivateKey) MarshalPrivateKey() []byte {
	return bigToFixedBytes(priv.D, 64)
}

// UnmarshalPrivateKey desserializa uma chave privada a partir de bytes
// big-endian (64 bytes).
func UnmarshalPrivateKey(data []byte) (*PrivateKey, error) {
	if len(data) != 64 {
		return nil, errors.New("m511: tamanho inválido de chave privada")
	}
	curve := M511()
	d := new(big.Int).SetBytes(data)
	if d.Sign() == 0 || d.Cmp(curve.Order) >= 0 {
		return nil, errors.New("m511: escalar privado fora do intervalo")
	}
	return &PrivateKey{D: d, Curve: curve}, nil
}

// Hex retorna a representação hexadecimal de uma chave pública.
func (pub *PublicKey) Hex() string {
	return hex.EncodeToString(pub.Marshal())
}

// Equal compara duas chaves públicas.
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if pub == nil || other == nil || pub.X == nil || other.X == nil {
		return false
	}
	return pub.X.Cmp(other.X) == 0
}

// -----------------------------------------------------------------------------
// Utilidades
// -----------------------------------------------------------------------------

// bigToFixedBytes codifica um big.Int em bytes big-endian de tamanho fixo.
func bigToFixedBytes(x *big.Int, size int) []byte {
	b := x.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// HexPrefix retorna os primeiros n caracteres da representação hexadecimal
// de x, preenchendo com zeros à esquerda se necessário.
func HexPrefix(x *big.Int, n int) string {
	s := x.Text(16)
	if len(s) < n {
		return fmt.Sprintf("%0*s", n, s)
	}
	return s[:n]
}

// MontgomeryLadder é a versão exportada de montgomeryLadder, para uso
// em testes e diagnóstico externos.
func MontgomeryLadder(curve *Curve, x *big.Int, k *big.Int) *big.Int {
	return montgomeryLadder(curve, x, k)
}
