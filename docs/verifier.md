# Verifier

## Overview

Renegade uses the Bulletproofs proof system for its zero-knowledge proofs. You can learn more about it by reading the [paper](https://eprint.iacr.org/2017/1066), or by going through the excellent documentation of the [Dalek implementation](https://doc-internal.dalek.rs/bulletproofs/notes/index.html), which cuts down to brass tacks a bit more and assumes very little familiarity with the proof system. We would recommend referring to this resource as you read through this document, as we use similar notation and a lot of the same implementation techniques.

These proofs are generated off-chain by [relayers](https://docs.renegade.fi/core-concepts/mpc-zkp#network-architecture) or by end-users themselves - either locally, or [collaboratively](https://docs.renegade.fi/core-concepts/mpc-zkp#collaborative-snarks), depending on the proof.

The verification of these proofs, on the other hand, takes place on-chain (in our case, on [Starknet](https://www.starknet.io/en)), and gates the updating of the global [commitment tree and nullifier set](https://docs.renegade.fi/core-concepts/mpc-zkp#the-commit-reveal-scheme). However, due to Bulletproofs verification having a computational complexity that is roughly linear with respect to the size of the circuit (i.e., the computation being proven), it is too costly to execute within a single Starknet transaction, given the size of our circuits. As such, our verifier is designed to be able to process the verification of any given proof over multiple transactions.

Before diving into this design, we'll give a (very brief and to-the-point) overview of Bulletproofs verification.

## Verification Algorithm

This overview of the verification algorithm does not delve into explaining _why_ the math is complete and sound, nor how the input variables are arrived at during proof generation. To gain an understanding of this, refer to the resources linked above.

### Verification Inputs

**Public circuit parameters:**
- $n$: The number of multiplication gates in the circuit
- $n^+$: $2^{\left \lceil{\log_2(n)} \right \rceil}$, i.e. the next power of 2 after/including $n$
- $k$: $\log_2(n^+)$
- $q$: The number of linear constraints in the circuit
- $m$: The number of elements in the witness
- $\vec{G}^+$: $n^+$-length vector of generators
- $\vec{H}^+$: $n^+$-length vector of generators
- $W_L$: $q \times n$ matrix of weights for left variables in linear constraints
- $W_R$: $q \times n$ matrix of weights for right variables in linear constraints
- $W_O$: $q \times n$ matrix of weights for output variables in linear constraints
- $W_V$: $q \times m$ matrix of weights for witness variables in linear constraints
- $\vec{c}$: $n$-length vector of constants in linear constraints
- $B$: Generator used in Pedersen commitments
- $\tilde{B}$: Generator used for blinding in Pedersen commitments

**Proof elements:**
- $A_I$: Pedersen commitment to input variables ($\vec{a}_L$ & $\vec{a}_R$)
- $A_O$: Pedersen commitment to output variables
- $S$: Pedersen commitment to variable blinding factors
- $T_1$, $T_3$, $T_4$, $T_5$, $T_6$: Pedersen commitments to inner-product polynomial coefficients
- $\hat{t}$: Evaluation of inner-product polynomial at challenge scalar $x$
- $\tilde{t}$: Synthetic blinding factor for inner-product polynomial
- $\tilde{e}$: Synthetic blinding factor for final commitment $P$
- $\vec{L}$: $k$-length vector of intermediary left cross-terms in inner-product argument
- $\vec{R}$: $k$-length vector of intermediary right cross-terms in inner-product argument
- $a$: Final left term of inner-product argument
- $b$: Final right term of inner-product argument
- $\vec{V}$: $m$-length vector of Pedersen commitments to witness variables

### Verification Operations

_Note: $`\langle \vec{a}, \vec{b} \rangle`$ denotes an inner product, i.e. $`\sum_i a_i \cdot b_i`$, however addition and multiplication are defined between elements of the vectors._

**Transcript & challenge generation:**

1. Verifier adds $\vec{V}, m, A_I, A_O, S$ to the transcript
2. Verifier squeezes challenge scalars $y, z$ out of the transcript
5. Verifier adds $T_1, T_3, T_4, T_5, T_6$ to the transcript
6. Verifier squeezes challenge scalar $x$ out of the transcript
7. Verifier adds $\hat{t}, \tilde{t}, \tilde{e}$ to the transcript
8. Verifier squeezes challenge scalar $w$ out of the transcript
9. Verifier squeezes IPA challenge scalars $\vec{u} = [u_1, …, u_k]$ out of the transcript
10. Verifier squeezes challenge scalar $r$ out of the transcript

**Intermediate scalar computation:**

_Note: The order here is not really relevant_

- Verifier computes:
    -  $\vec{y}^{-n^+} = [1, y^{-1}, y^{-2}, ..., y^{-(n^+-1)}]$
    - $z\vec{z}^{q} = [z, z^2, ..., z^q]$
- Verifier computes “flattened” weight vectors & flattened constant term:
    - $\vec{w}_L = z\vec{z}^{q} \cdot W_L$
    - $\vec{w}_R = z\vec{z}^{q} \cdot W_R$
    - $\vec{w}_O = z\vec{z}^{q} \cdot W_O$
    - $\vec{w}_V = z\vec{z}^{q} \cdot W_V$
    - $w_c = z\vec{z}^{q} \cdot \vec{c}$
- Verifier computes $\vec{u}^2 = [u_1^2, ..., u_k^2], \vec{u}^{-2} = [u_1^{-2}, ..., u_k^{-2}]$ from $\vec{u}$
- Verifier computes generator coefficients $\vec{s}, \vec{s}^{-1}$ for the inner-product argument from $\vec{u}$
    - $\vec{s}$ is given by $s_i = u_k^{b(i,k)} \cdot\cdot\cdot u_1^{b(i,1)}$, where $`b(i, j) =
    \begin{cases}
      -1, & \text{if bit } j-1 \text{ of } i=0 \\
      +1, & \text{if bit } j-1 \text{ of } i=1
    \end{cases}`$
    - $\vec{s}^{-1}$ is just the reverse of $\vec{s}$
- Verifier computes $\delta(y, z) = \langle \vec{y}^{-n^+}_{[0:n]} \circ \vec{w}_R, \vec{w}_L \rangle$

**Final MSM:**

The actual verification is one large MSM (multi-scalar multiplication) check of the following form:

```math
\begin{aligned}
0 \stackrel{?}{=}
\space &x \cdot A_I \\
+ \space & x^2 \cdot A_O \\
+ \space & x^3 \cdot S \\
+ \space & \langle rx^2\vec{w}_V, \vec{V} \rangle \\
+ \space & \sum_{i \in\{1, 3, 4, 5, 6\}}rx^i \cdot T_i \\
+ \space & (w(\hat{t}-ab)+r(x^2(w_c+\delta(y, z))-\hat{t})) \cdot B \\
+ \space & (-\tilde{e}-r\tilde{t}) \cdot \tilde{B} \\
+ \space & \langle \vec{u}^2, \vec{L} \rangle \\
+ \space & \langle \vec{u}^{-2}, \vec{R} \rangle \\
+ \space & \langle x \vec{y}^{-n^+}_{[0:n]} \circ \vec{w}_R - a\vec{s}_{[0:n]}, \vec{G}^+_{[0:n]} \rangle \\
+ \space & \langle -a \vec{s}_{[n:n^+]}, \vec{G}^+_{[n:n^+]} \rangle \\
+ \space & \langle -\vec{1}+\vec{y}^{-n^+}_{[0:n]} \circ (x\vec{w}_L+\vec{w}_O-b\vec{s}^{-1}_{[0:n]}), \vec{H}^+_{[0:n]} \rangle \\
+ \space & \langle -\vec{1}+\vec{y}^{-n^+}_{[n:n^+]} \circ (-b\vec{s}^{-1}_{[n:n^+]}), \vec{H}^+_{[n:n^+]} \rangle \\
\end{aligned}
```

Which contains $10 + m + 2n + 2\log_2(n)$ terms.

## Implementation Design

The main obstacle to work around when implementing the above on-chain is compute limits. In Starknet, a given transaction can currently only execute [1M Cairo steps](https://docs.starknet.io/documentation/starknet_versions/limits_and_triggers/). Some conservative benchmarking of our circuits, which have $n \in \mathcal{O}(10,000)$, quickly revealed that verifying a proof in a single transaction is infeasible (these constants really do stack up!)

As such, we had to devise a design that allows processing the verification of a proof across multiple transactions.

### Step Verification

The computation done throughout verification is quite homogenous at a high level: get the next scalar, get the next elliptic curve point, compute their product, add it to an accumulated result, and repeat. Our verifier design revolves around this mechanic of incrementally processing the MSM, which looks something like this:

```python
def step_verification():
    msm_result = storage.read("msm_result")

    while msm_not_done() and enough_gas_remaining():
        scalar = get_next_scalar()
        point = get_next_point()

        msm_result += scalar * point

    storage.write("msm_result", msm_result)
```

A relayer or user can send as many transactions as necessary invoking `step_verification` until all the scalars / points are processed.

### Two-Part Processing

Since verifying a proof now requires some intermediary state to be stored on the contract, we introduce the notion of a "verification job," which groups together all of the information used in the verification of a given proof, and has roughly the following shape:

```rust
struct VerificationJob {
    remaining_scalars: Array<Scalar>,
    remaining_points: Array<EcPoint>,
    msm_result: EcPoint,
    verified: Option<bool>,
}
```

Verifying a proof, then, is split across **two** functions: `queue_verification_job`, and `step_verification`. An intuition for the latter is given above.

`queue_verification_job` can be thought to do the following:

```python
def queue_verification_job(proof, verification_job_id):
    challenge_scalars = squeeze_challenge_scalars(proof)
    remaining_scalars = prep_scalars(challenge_scalars, proof)

    generators = storage.read("generators")
    remaining_points = prep_points(generators, proof)

    verification_job = new_verification_job(
        remaining_scalars,
        remaining_points,
        0, # Initial MSM result
        None, # Initial verification status
    )

    storage.write(verification_job_id, verification_job)
```

In essence, it assembles the lists of scalars & points to be used in the verification MSM by `step_verification`.

### Scalar Polynomial Representation

Unfortunately, evaluating and storing all of the scalars used for the verification MSM in `queue_verification_job` is infeasible because of the storage costs. For our circuits, there are $\mathcal{O}({100,000})$ terms in the MSM - storing a scalar for each is overwhelmingly expensive.

Instead, we store a constant number of _polynomials_ over _vectors_ of scalars on the contract - the exact same polynomials in the MSM check laid out above, e.g. this cute fella:

```math
-\vec{1}+\vec{y}^{-n^+}_{[0:n]} \circ (x\vec{w}_L+\vec{w}_O-b\vec{s}^{-1}_{[0:n]})
```

Then, in `step_verification`, we evaluate the vector polynomial at its next index (which is stored on the contract), until all of its elements are exhausted, at which point we move on to the next.

The same intuition extends to the elliptic curve points in the MSM, primarily the $\vec{G}^+$ and $\vec{H}^+$ generators. For these, each successive generator is sampled from a hash chain, so we simply store the current hash state on the contract.

### Sparse-Reduced Weight Vectors

One final high-level design element worth considering stems from the observation that the circuit weights $W_{\{L,R,O,V\}}, \vec{c}$ are incredibly sparse.

As such, we store & operate on them in "sparse-reduced" form: each vector is represented as a list of `(index, weight)` tuples, ordered by increasing `index`, for the indices and weights of the non-zero elements of the vector. For the matrices, this means each row is represented in this form.

This greatly reduces storage expenses, at the cost of some implementation complexity.
