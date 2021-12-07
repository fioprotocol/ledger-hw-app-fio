# Get Public Key

**Description**

Get a public key for a given BIP32 path. 

**Command**

| Field | Value    |
| ----- | -------- |
| CLA   | `0xD7`   |
| INS   | `0x10`   |
| P1    | show (`0x01`) or not (`0x02`) |
| P2    | unused   |
| Lc    | variable |

The public key and derivation path will be shown either way if the derivation path is suspicious.

**Data**

| Field                             | Length | Comments                           |
| --------------------------------- | ------ | ---------------------------------- |
| BIP32 path len                    | 1      | min 2, max 10                      |
| First derivation index            | 4      | Big endian. Must be 44'            |
| Second derivation index           | 4      | Big endian. Must be 235'           |
| (optional) Third derivation index | 4      | Big endian                         |
| ...                               | ...    | ...                                |
| (optional) Last derivation index  | 4      | Big endian                         |
| (optional) No. of remaining keys  | 4      | Big endian                         |

Ledger will will process only certain paths, other paths will be rejected by app policy (see Ledger responsibilities section). 

**Response**

| Field       | Length |
| ----------- | ------ |
| pub_key     | 65     |
| pub_key_WIF | 53     |

**Errors (SW codes)**

- `0x9000` OK
- `0x6E10` Request rejected by app policy
- `0x6E09` Request rejected by user
- for more errors, see [src/errors.h](../src/errors.h)

**Ledger responsibilities**

- Check:
  - check P1 is valid
    - `P1 == 0`
  - check P2 is valid
    - `P2 == 0`
  - check data is valid:
    - `Lc >= 1` (we have path_len)
    - `1 + path_len * 4 == Lc`
  - check derivation path is valid and within FIO BIP32 space
    - `path_len == 5`
    - `path[0] == 44'` (' means hardened)
    - `path[1] == 235'`
    - `path[2] == 0'` 
    - `path[3] == 0` 
    - Ledger might impose more restrictions, see implementation of `policyForGetPublicKey` in [src/securityPolicy.c](../src/securityPolicy.c) for details
- calculate public key
- respond with public key
 

