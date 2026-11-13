# Subpolicy applied on top of FUTURE: FUTURE:INTERNET-COMPAT.
#
# FUTURE in this crypto-policies release allows only post-quantum hybrid key
# exchange (ML-KEM-768 + X25519 and similar) and refuses RSA keys under
# 3072 bits. Tested from this image, that made every TLS handshake with
# quay.io (the registry bootc upgrades from), github.com and three of the
# four NTS time servers fail: those servers do not offer ML-KEM, and their
# certificates or CA chains use RSA-2048. See docs/verification/crypto-policy.txt.
#
# This module keeps everything else in FUTURE (TLS 1.3 only, AES-256-GCM,
# AES-256-CCM and ChaCha20-Poly1305 only, no SHA-1, no CBC in SSH) and:
#  - appends classical ECDHE groups AFTER the hybrids, so a server that
#    supports ML-KEM still gets it, and one that doesn't still connects;
#  - accepts RSA keys of 2048 bits, the size almost every public CA and
#    server certificate uses today.
group = +X25519 +SECP256R1 +SECP384R1
key_exchange = +ECDHE
min_rsa_size = 2048
