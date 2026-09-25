# ECDH sobre a Curva M-511
M-511 Montgomery ECDH Function

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
\# E(\mathbb{F}_p) = h \cdot n
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
