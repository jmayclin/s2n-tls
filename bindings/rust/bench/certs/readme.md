This folder actually just contains symlinks to the files in s2n-tls/test/pems/permutations

```
ln -s ../../../../tests/pems/permutations/ec_ecdsa_p256_sha256 ecdsa256
ln -s ../../../../tests/pems/permutations/ec_ecdsa_p384_sha384 ecdsa384
ln -s ../../../../tests/pems/permutations/ec_ecdsa_p521_sha512 ecdsa521
ln -s ../../../../tests/pems/permutations/rsae_pkcs_2048_sha256 rsa2048
ln -s ../../../../tests/pems/permutations/rsae_pkcs_3072_sha384 rsa3072
ln -s ../../../../tests/pems/permutations/rsae_pkcs_4096_sha384 rsa4096
ln -s ../../../../tests/pems/permutations/rsapss_pss_2048_sha256 rsapss2048
```
