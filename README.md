# ECDH sobre a Curva M-511
M-511 Montgomery ECDH Function

**M-511** is a 511-bit Montgomery elliptic curve proposed in 2013 by Diego F. Aranha, Paulo S. L. M. Barreto, Geovandro C. C. F. Pereira, and Jefferson Ricardini in *"A note on high-security general-purpose elliptic curves"* ([https://eprint.iacr.org/2013/647](https://eprint.iacr.org/2013/647)), defined over the prime field $\mathbb{F}_p$ with $p = 2^{511} - 187$ and equation $y^2 = x^3 + A x^2 + x \pmod{p}$ where $A = 530438$, offering approximately **256 bits of classical security** against the best known attack (Pollard's rho, with complexity $O(\sqrt{n}) \approx O(2^{256}))$; it is intended for ephemeral Elliptic Curve Diffie-Hellman (**ECDHE**) key agreement, where two parties each generate a private scalar $d \in [1, n-1]$ and a public point $Q = dG$ (with $G = (5, \ldots)$ the generator and $n = 2^{256} \cdot (2^{255} - 765)$ the prime subgroup order), exchange public keys over an insecure channel, and independently compute the shared secret $S = d_A Q_B = d_B Q_A$, using the **Montgomery ladder** for constant-sequence scalar multiplication and **point compression** (64-byte big-endian encoding of the $x$-coordinate only) to halve public key size.

## 1. Corpo finito

Seja o corpo primo $\mathbb{F}_p$, onde

$$
p = 2^{511} - 187
$$

Em hexadecimal:

$$
p = \texttt{0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF45}
$$

Todos os elementos de $\mathbb{F}_p$ são inteiros em $[0, p-1]$, com adição e multiplicação módulo $p$.

---

## 2. Curva de Montgomery

A curva M-511 é uma **curva de Montgomery** definida por

$$
B \cdot y^2 \equiv x^3 + A \cdot x^2 + x \pmod{p}
$$

com

$$
A = \texttt{0x081806} = 530438, \qquad B = 1
$$

Como $B = 1$, a equação se simplifica para

$$
y^2 = x^3 + A x^2 + x \pmod{p}
$$

### 2.1 Ordem e cofator

O grupo de pontos da curva tem ordem

$$
\lvert E(\mathbb{F}_p) \rvert = h \cdot n
$$

onde

- $h = 8$ é o **cofator**,
- $n$ é a **ordem do subgrupo de ordem prima**:

$$
n = 2^{256} \cdot \left(2^{255} - 765\right)
$$

Em hexadecimal:

$$
n = \texttt{0x100000000000000000000000000000000000000000000000000000000000000017B5FEFF30C7F5677AB2AEEBD13779A2AC125042A6AA10BFA54C15BAB76BAF1B}
$$

### 2.2 Ponto gerador

O ponto gerador é

$$
G = (x_G, y_G) = \left(\texttt{0x05},\ \texttt{0x2fbd...fa5}\right)
$$

Apenas a coordenada $x_G = 5$ é usada para ECDH; a coordenada $y$ é recuperável a partir de $x$.

---

## 3. Operações no grupo

### 3.1 Adição de pontos

Dados $P = (x_1, y_1)$ e $Q = (x_2, y_2)$ na curva, com $P \neq \pm Q$, a soma $R = P + Q = (x_3, y_3)$ é

$$
x_3 = \lambda^2 - A - x_1 - x_2 \pmod{p}
$$

$$
y_3 = \lambda (x_1 - x_3) - y_1 \pmod{p}
$$

onde

$$
\lambda = \frac{y_2 - y_1}{x_2 - x_1} \pmod{p}
$$

### 3.2 Duplicação de pontos

Para $P = (x_1, y_1)$ com $y_1 \neq 0$, a duplicação $R = 2P = (x_3, y_3)$ é

$$
x_3 = \lambda^2 - A - 2x_1 \pmod{p}
$$

$$
y_3 = \lambda (x_1 - x_3) - y_1 \pmod{p}
$$

onde

$$
\lambda = \frac{3x_1^2 + 2A x_1 + 1}{2 y_1} \pmod{p}
$$

### 3.3 Multiplicação escalar

Para $k \in \mathbb{Z}$ e $P$ na curva,

$$
kP = \underbrace{P + P + \cdots + P}_{k \text{ vezes}}
$$

Para $k < 0$, define-se $kP = (-k)(-P)$.

---

## 4. Coordenadas projetivas e a escada de Montgomery

Para evitar inversões modulares, usa-se **coordenadas projetivas** $(X : Z)$, onde a coordenada afim é

$$
x = \frac{X}{Z} \pmod{p}
$$

### 4.1 Fórmulas de duplicação

Para $P = (X : Z)$, a duplicação $2P = (X' : Z')$ é

$$
X' = (X + Z)^2 (X - Z)^2 \pmod{p}
$$

$$
Z' = \left[ (X - Z)^2 + a_{24} \cdot \left( (X + Z)^2 - (X - Z)^2 \right) \right] \cdot \left( (X + Z)^2 - (X - Z)^2 \right) \pmod{p}
$$

onde

$$
a_{24} = \frac{A - 2}{4} \pmod{p}
$$

Para M-511:

$$
a_{24} = \frac{530438 - 2}{4} = \frac{530436}{4} = 132609
$$

> **Observação:** a fórmula correta usa $A - 2$, não $A + 2$.

### 4.2 Fórmulas de adição diferencial

Dados $P = (X_2 : Z_2)$ e $Q = (X_3 : Z_3)$ com diferença conhecida $P - Q = (X_1 : Z_1)$, a soma $R = P + Q = (X' : Z')$ é

$$
X' = Z_1 \cdot \left[ (X_2 - Z_2)(X_3 + Z_3) + (X_2 + Z_2)(X_3 - Z_3) \right]^2 \pmod{p}
$$

$$
Z' = X_1 \cdot \left[ (X_2 - Z_2)(X_3 + Z_3) - (X_2 + Z_2)(X_3 - Z_3) \right]^2 \pmod{p}
$$

Na escada de Montgomery, a diferença é sempre o ponto base $P_0 = (x_1 : 1)$, então $X_1 = x_1$ e $Z_1 = 1$.

### 4.3 Escada de Montgomery

Dado

$$
k = \sum_{i=0}^{L-1} k_i \cdot 2^i, \qquad k_i \in \{0, 1\}
$$

a escada de Montgomery calcula $kP$ processando os bits de $k$ do mais significativo ($k_{L-1}$) ao menos significativo ($k_0$). Mantêm-se dois pontos $R_0$ e $R_1$ com a invariante

$$
R_1 - R_0 = P
$$

A cada iteração, para o bit $k_i$:

- **Se $k_i = 0$:**

$$
(R_0, R_1) \leftarrow (2R_0,\ R_0 + R_1)
$$

- **Se $k_i = 1$:**

$$
(R_0, R_1) \leftarrow (R_0 + R_1,\ 2R_1)
$$

Após processar todos os bits, $R_0 = kP$.

**Complexidade:** $L$ iterações, cada uma com 1 duplicação e 1 adição diferencial. Total: $O(L)$ operações no corpo.

**Resistência a canal lateral:** a sequência de operações é a mesma independentemente dos bits de $k$, o que torna a escada naturalmente resistente a ataques de temporização simples (SPA). No entanto, implementações com `math/big` quebram essa garantia, pois as operações de corpo não são constant-time.

---

## 5. Geração de chaves

A chave privada é um escalar

$$
d \in [1, n-1]
$$

gerado uniformemente ao acaso. A chave pública é o ponto

$$
Q = dG = d \cdot (x_G, y_G)
$$

que, em coordenadas de Montgomery, é representada apenas pela coordenada $x$:

$$
Q_x = \text{ladder}(x_G, d)
$$

---

## 6. ECDH (Diffie–Hellman de Curva Elíptica)

### 6.1 Protocolo

1. **Alice** gera $d_A \in [1, n-1]$ e calcula $Q_A = d_A G$.
2. **Bob** gera $d_B \in [1, n-1]$ e calcula $Q_B = d_B G$.
3. Alice e Bob trocam $Q_A$ e $Q_B$ por um canal público.
4. **Alice** calcula $S = d_A Q_B$.
5. **Bob** calcula $S = d_B Q_A$.

### 6.2 Correção

O segredo compartilhado é o mesmo:

$$
S = d_A Q_B = d_A (d_B G) = (d_A d_B) G = d_B (d_A G) = d_B Q_A
$$

### 6.3 Segredo compartilhado

Apenas a coordenada $x$ de $S$ é usada:

$$
S_x = \text{ladder}(Q_{B,x}, d_A) = \text{ladder}(Q_{A,x}, d_B)
$$

Codificado em **64 bytes big-endian**.

---

## 7. Validação de ponto

### 7.1 Ponto na curva

Um candidato a coordenada $x$ está na curva se e somente se

$$
x^3 + A x^2 + x \pmod{p}
$$

é um **resíduo quadrático** módulo $p$. Pelo critério de Euler:

$$
\left( x^3 + A x^2 + x \right)^{\frac{p-1}{2}} \equiv 1 \pmod{p}
$$

Se a congruência vale, existe $y$ tal que $(x, y)$ satisfaz a equação da curva.

### 7.2 Subgrupo de ordem prima

Para evitar ataques de subgrupo pequeno, verifica-se se o ponto $Q$ está no subgrupo de ordem prima:

$$
n \cdot Q = \mathcal{O}
$$

onde $\mathcal{O}$ é o ponto no infinito. Para M-511, o gerador $G$ **não** está no subgrupo de ordem prima; ele está no subgrupo completo de ordem $h \cdot n = 8n$. Nesse caso, aplica-se **cofactor clearing**:

$$
Q' = h \cdot Q = 8Q
$$

e verifica-se $n \cdot Q' = \mathcal{O}$.

---

## 8. Recuperação da coordenada $y$

Dado $x$, a coordenada $y$ é obtida resolvendo

$$
y^2 = x^3 + A x^2 + x \pmod{p}
$$

Para $p \equiv 1 \pmod{4}$, usa-se o algoritmo de **Tonelli–Shanks** para calcular a raiz quadrada modular. A convenção adotada é escolher a raiz **par** (bit menos significativo igual a $0$).

---

## 9. Serialização

### 9.1 Chave privada

O escalar $d$ é serializado em **64 bytes big-endian**:

$$
d = \sum_{i=0}^{63} b_i \cdot 256^{63-i}, \qquad b_i \in [0, 255]
$$

### 9.2 Chave pública

A coordenada $x$ de $Q$ é serializada em **64 bytes big-endian**.

### 9.3 PKCS#8 e PKIX

A chave privada é encapsulada em `PrivateKeyInfo`:

```
PrivateKeyInfo ::= SEQUENCE {
    version             INTEGER,
    privateKeyAlgorithm AlgorithmIdentifier,
    privateKey          OCTET STRING
}
```

A chave pública é encapsulada em `SubjectPublicKeyInfo`:

```
SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm           AlgorithmIdentifier,
    subjectPublicKey    BIT STRING
}
```

O `AlgorithmIdentifier` usa o OID

$$
\text{oid}_{M\text{-}511} = 1.3.6.1.4.1.99999.1.1
$$

---

## 10. Tabela de símbolos

| Símbolo | Significado |
|---|---|
| $p$ | Primo do corpo finito, $2^{511} - 187$ |
| $\mathbb{F}_p$ | Corpo finito de ordem $p$ |
| $A$ | Coeficiente da curva de Montgomery, $530438$ |
| $B$ | Coeficiente da curva, $1$ |
| $E$ | Conjunto de pontos da curva |
| $h$ | Cofator, $8$ |
| $n$ | Ordem do subgrupo de ordem prima |
| $G$ | Ponto gerador |
| $d$ | Escalar da chave privada |
| $Q$ | Ponto da chave pública |
| $S$ | Segredo compartilhado |
| $\mathcal{O}$ | Ponto no infinito |
| $a_{24}$ | Constante $(A - 2)/4$ |

---

## 11. Resumo do algoritmo ECDH M-511

$$
\boxed{
\begin{aligned}
&\text{1. } d_A, d_B \xleftarrow{\$} [1, n-1] \\
&\text{2. } Q_A = \text{ladder}(x_G, d_A), \quad Q_B = \text{ladder}(x_G, d_B) \\
&\text{3. Trocar } Q_A, Q_B \\
&\text{4. } S = \text{ladder}(Q_{B,x}, d_A) = \text{ladder}(Q_{A,x}, d_B) \\
&\text{5. Retornar } S \text{ em 64 bytes big-endian}
\end{aligned}
}
$$

A segurança do ECDH repousa na dificuldade do **Problema do Logaritmo Discreto em Curva Elíptica (ECDLP)**: dados $G$ e $Q = dG$, encontrar $d$ é computacionalmente inviável para curvas bem escolhidas. Para M-511, o melhor algoritmo conhecido (Pollard's rho) requer aproximadamente

$$
O(\sqrt{n}) \approx O(2^{256})
$$

operações, o que é inviável com a tecnologia atual.

## Exemplo de Uso

```go
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/pedroalbanese/m511"
)

func main() {
	fmt.Println("=== ECDH M-511 — Teste Completo com PKCS#8 ===")
	fmt.Println()

	c := m511.M511()
	fmt.Printf("p        = %s...\n", m511.HexPrefix(c.P, 32))
	fmt.Printf("A        = 0x%s\n", c.A.Text(16))
	fmt.Printf("Order    = %s...\n", m511.HexPrefix(c.Order, 32))
	fmt.Printf("Cofactor = %d\n", c.Cofactor)
	fmt.Println()

	// 1. Gera chaves.
	alicePriv, alicePub, err := m511.GenerateKeyWithReader(rand.Reader)
	if err != nil {
		panic(err)
	}
	bobPriv, bobPub, err := m511.GenerateKeyWithReader(rand.Reader)
	if err != nil {
		panic(err)
	}

	fmt.Println("--- 1. Chaves geradas ---")
	fmt.Printf("Alice priv (D)  = %s...\n", m511.HexPrefix(alicePriv.D, 32))
	fmt.Printf("Alice pub  (X)  = %s...\n", m511.HexPrefix(alicePub.X, 32))
	fmt.Printf("Bob   priv (D)  = %s...\n", m511.HexPrefix(bobPriv.D, 32))
	fmt.Printf("Bob   pub  (X)  = %s...\n", m511.HexPrefix(bobPub.X, 32))
	fmt.Println()

	// 2. Marshal/Unmarshal chave privada (64 bytes).
	fmt.Println("--- 2. Marshal/Unmarshal de chave privada (64 bytes) ---")
	privBytes := alicePriv.MarshalPrivateKey()
	fmt.Printf("Tamanho: %d bytes\n", len(privBytes))
	alicePriv2, err := m511.UnmarshalPrivateKey(privBytes)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Round-trip OK: %v\n", alicePriv.D.Cmp(alicePriv2.D) == 0)
	fmt.Println()

	// 3. Marshal/Unmarshal chave pública (64 bytes).
	fmt.Println("--- 3. Marshal/Unmarshal de chave pública (64 bytes) ---")
	pubBytes := alicePub.Marshal()
	fmt.Printf("Tamanho: %d bytes\n", len(pubBytes))
	alicePub2, err := m511.UnmarshalPublicKey(pubBytes)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Round-trip OK: %v\n", alicePub.Equal(alicePub2))
	fmt.Println()

	// 4. PKCS#8.
	fmt.Println("--- 4. PKCS#8 (chave privada) ---")
	alicePKCS8, err := alicePriv.MarshalPKCS8PrivateKey()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Tamanho DER: %d bytes\n", len(alicePKCS8))
	fmt.Printf("DER (hex):   %s\n", hex.EncodeToString(alicePKCS8))
	alicePriv3, err := m511.ParsePKCS8PrivateKey(alicePKCS8)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Round-trip OK: %v\n", alicePriv.D.Cmp(alicePriv3.D) == 0)
	fmt.Println()

	// 5. PKIX.
	fmt.Println("--- 5. PKIX (chave pública) ---")
	alicePKIX, err := alicePub.MarshalPKIXPublicKey()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Tamanho DER: %d bytes\n", len(alicePKIX))
	fmt.Printf("DER (hex):   %s\n", hex.EncodeToString(alicePKIX))
	alicePub3, err := m511.ParsePKIXPublicKey(alicePKIX)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Round-trip OK: %v\n", alicePub.Equal(alicePub3))
	fmt.Println()

	// 6. ECDH com chaves PKCS#8/PKIX.
	fmt.Println("--- 6. ECDH com chaves PKCS#8/PKIX ---")
	alicePrivPKCS8, err := m511.ParsePKCS8PrivateKey(alicePKCS8)
	if err != nil {
		panic(err)
	}
	bobPKIX, err := bobPub.MarshalPKIXPublicKey()
	if err != nil {
		panic(err)
	}
	bobPubPKIX, err := m511.ParsePKIXPublicKey(bobPKIX)
	if err != nil {
		panic(err)
	}
	aliceShared, err := alicePrivPKCS8.ECDH(bobPubPKIX)
	if err != nil {
		panic(err)
	}
	bobShared, err := bobPriv.ECDH(alicePub3)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Alice calcula: %s\n", hex.EncodeToString(aliceShared))
	fmt.Printf("Bob   calcula: %s\n", hex.EncodeToString(bobShared))
	fmt.Println()
	if bytes.Equal(aliceShared, bobShared) {
		fmt.Println("✓ SUCESSO: ECDH com chaves PKCS#8/PKIX funcionou!")
	} else {
		fmt.Println("✗ FALHA: segredos compartilhados diferentes!")
	}
	fmt.Println()

	// 7. Testes de rejeição.
	fmt.Println("--- 7. Testes de rejeição ---")

	// 7.1. PKCS#8 com OID errado.
	wrongOID := append([]byte{}, alicePKCS8...)
	wrongOID[10] ^= 0xFF
	_, err = m511.ParsePKCS8PrivateKey(wrongOID)
	fmt.Printf("PKCS#8 com OID errado rejeitado: %v\n", err != nil)

	// 7.2. PKIX truncado.
	truncated := alicePKIX[:len(alicePKIX)-10]
	_, err = m511.ParsePKIXPublicKey(truncated)
	fmt.Printf("PKIX truncado rejeitado: %v\n", err != nil)

	// 7.3. Chave privada com D = 0.
	zeroD := make([]byte, 64)
	type pkcs8Raw struct {
		Version             int
		PrivateKeyAlgorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		PrivateKey []byte
	}
	infoRaw := pkcs8Raw{
		Version: 0,
		PrivateKeyAlgorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}{
			Algorithm:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1},
			Parameters: asn1.RawValue{Tag: asn1.TagOID},
		},
		PrivateKey: zeroD,
	}
	zeroPKCS8, err := asn1.Marshal(infoRaw)
	if err != nil {
		panic(err)
	}
	_, err = m511.ParsePKCS8PrivateKey(zeroPKCS8)
	fmt.Printf("PKCS#8 com D=0 rejeitado: %v\n", err != nil)

	// 7.4. Chave pública com X >= p.
	bigX := new(big.Int).Add(c.P, big.NewInt(1))
	bigXBytes := make([]byte, 64)
	bigX.FillBytes(bigXBytes)
	type pkixRaw struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		SubjectPublicKey asn1.BitString
	}
	pkixInfoRaw := pkixRaw{}
	pkixInfoRaw.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	pkixInfoRaw.Algorithm.Parameters = asn1.RawValue{Tag: asn1.TagOID}
	pkixInfoRaw.SubjectPublicKey = asn1.BitString{
		Bytes:     bigXBytes,
		BitLength: len(bigXBytes) * 8,
	}
	bigPKIX, err := asn1.Marshal(pkixInfoRaw)
	if err != nil {
		panic(err)
	}
	_, err = m511.ParsePKIXPublicKey(bigPKIX)
	fmt.Printf("PKIX com X >= p rejeitado: %v\n", err != nil)

	fmt.Println()
	fmt.Println("=== Fim dos testes ===")
}
```

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2026 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
