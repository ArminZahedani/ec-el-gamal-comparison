# EC-El-Gamal-Comparison
An implementation of a 2-Party-comparison protocol using Scicrypt.

# Introduction
Suppose Alice holds two integers, [a], [b] encrypted with the public key of Bob. Alice (and perhaps Bob) would like to learn whether `a < b` without revealing a, b to Bob, nor any other information. They both do not have access to a trusted third party that computes this for them. However, Alice and Bob can interact and figure this out by themselves using Cryptography.

# The Scheme
The scheme is by Nateghizad et al. and can be found [here](https://www.researchgate.net/publication/303317622_An_efficient_privacy-preserving_comparison_protocol_in_smart_metering_systems). In essence, we implement the same scheme, but instead of using DGK, we use Elliptic-Curve-El-Gamal, implemented by (Scicrypt)[https://github.com/jellevos/scicrypt]. This makes key-generation and public key operations super fast :zap:

# How to use
Examples on how the protocol can be used can be found in `tests/comparison.rs`
