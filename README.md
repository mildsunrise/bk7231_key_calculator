# [BK7231][] key calculator

Given an encrypted image (and the base address it is mapped at), this tool searches for a string
in its *decrypted* contents and, if an occurrence is found, prints the key that decrypts the
occurrence. Sometimes the same occurrence is compatible with multiple keys; multiple searches may
be needed to fully pinpoint the key. Occurrences at very low addresses tend to work well.

The image and base address must *not* include CRC bytes (encrypted/decrypted bytes are contiguous).

Example:
~~~
$ ./bk7231_key_calculator encrypted_bootloader.bin 0 'incorrect header check'
Found match at 0x570 with key: 0 0 7cb50721 55000803
~~~

Limitations:
- Occurrences of the string in the first 4 bytes of the image are currently not found.
- The string must be at least 9 bytes in length (8 is the mathematical minimum, but the tool
  requires one more to simplify the search optimization).
- This will not give the exact key in efuse, but an equivalent key. This key causes the cipher
  to behave in the same way for all inputs, so it allows encrypting and decrypting for that device.
- Although the search algorithm takes any byte sequence, the CLI isn't prepared to receive
  anything other than text. If you need to search for binary data, please modify the code.

## How it works

This tool doesn't actually try all possible keys in all possible offsets, it just preprocesses
the image and search string with a simple manipulation and then does a normal search of the
(preprocessed) search string inside the (preprocessed) image. This search gives a hit exactly
when there exists a key that decrypts to the occurrence, i.e. we can search in the decrypted
contents without actually knowing the key. Once an occurrence is found, finding the key that
produces it is also trivial.

All this is thanks to BK7231's encryption being so comically flawed as to not even qualify
for being called "encryption". "Obfuscation" would be a better name.

### The technical details

As explained in [this introductory gist][intro], of the four 32-bit words that make up a key,
only the first three have the role of "key material". The last one is a "settings bitfield":
most of its bits are ignored, but a few of them turn the different "stages" on and off, as
well as select between a whopping 4 configurations for each of the stages. Oh, and one of
its bits *does* serve as key material (it is joined with the second word).

So already, we don't have a 128-bit key, but a 97-bit one.

As for the settings word, most of the bits are always ignored (as mentioned above) but some
bits can cause other bits to be ignored, too. Disabling a stage causes not just the 2-bit
"configuration selector" for that stage to be ignored, but the key material for the
stage too. Stages 1, 2, 3 can be either disabled or in one of 4 configurations, and stage 4
can only be enabled or disabled. That means all settings words can be grouped into
$5^3 2 = 250$ buckets whose words can be used interchangeably. Furthermore, disabling stage 4
has the same effect as keeping it enabled but with its key material (the third word) set to 0.
So effectively we have only $5^3 = 125$ settings combinations.

Now, the big failure here is that, for a given (fixed) settings combination, the output is
a *linear transform* of the bits in the input and the bits in the "key material". This has
three main consequences:

 - We can just solve for the key. This cipher, like any linear system, is trivially reversible.

 - Most of the 97-bit key material is redundant; since it is a linear transform, the effective
   key size cannot be more than the output size (which is 32 bits). This means all of the 2^97
   keys can be grouped in at most 2^32 buckets of keys that all have the same effect.

 - If we don't really care about the actual key and just want to be able to decrypt and
   encrypt things *just as if we had it*, things become even easier: by superposition, the
   cipher can be modelled as $E(K, P) = F(K) \oplus G(P)$ (where $F(K) = E(K, 0)$ and
   $G(P) = E(0, P)$ ). That is, the input is being transformed linearly in some way, and the
   cipher is then XORing in an unknown value $F(K)$, the same value for all blocks. So finding
   the $F(K)$ value is enough, and it can be easily calculated if we know a plaintext-ciphertext
   pair: $F(K) = G(P) \oplus C$.

To make things even easier, the structure of this particular linear transform makes it easy to
reverse $E$ to get a key that has equivalent effects: set all of $K$ (the key material) to zero
except for the third word which will hold $F(K)$ (since that word is XORed with the rest).


[BK7231]: https://docs.libretiny.eu/docs/platform/beken-72xx/
[intro]: https://gist.github.com/mildsunrise/7e5b7f755e99fca5639619e1a6152679
