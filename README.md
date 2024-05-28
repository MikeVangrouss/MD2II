# MD2II Hash Function
MD2II Hash function for creating encryption keys.

MD2II was released in 2005. This is a one-way hash function based on MD2 by Ron Rivest with a variable-size hash. MD2II cannot be used as a general one-way hash function but only to hash passwords to create keys or subkeys for block cipher algorithms.

Thus, MD2II is not vulnerable to the preimage or collision attack since the generated hash is not accessible to the attacker.

Generating the subkeys of a block cipher algorithm by MD2II prevents attacks on the keys for that algorithm making it impossible Related-key_attack.
