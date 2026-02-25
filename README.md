# BitwardenCrackle

This is a slightly modified version of [BitwardenDecryptBrute](https://github.com/S3cur3Th1sSh1t/BitwardenDecryptBrute). In addition to the decryption this version includes wordlist generation.

### Usage: 
```
bash decrypt.sh /path/to/data.json /path/to/wordlist.txt
```

Decrypts an encrypted [Bitwarden](https://github.com/bitwarden) data.json file.
You can safely store data.json as an encrypted, offline backup of your vault knowing you will always be able to decrypt it.

To determine the location of the data.json file see:  
https://bitwarden.com/help/article/where-is-data-stored-computer/

*Note: BitwardenDecrypt does not work with Bitwarden Encrypted JSON Exports.<br/>
These exports lack the Protected Symmetric Key needed to decrypt entries.*

## Limitations

- Does not work with Bitwarden Encrypted JSON Exports.
<br/>*These exports lack the Protected Symmetric Key needed to decrypt entries.*
- Can only decrypt EncryptionType: 2 (AesCbc256_HmacSha256_B64). At the time of writing this is the default used for all entries in the personal vault.
- Initial support for decrypting items from a Collection (Organization). This adds support for decrypting EncryptionType: 4 (Rsa2048_OaepSha1_B64)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details

## Acknowledgments

* [Kyle Spearrin](https://github.com/kspearrin) for creating [Bitwarden](https://github.com/bitwarden).
* Joshua Stein ([Rubywarden](https://github.com/jcs/rubywarden)) for the reverse engineered Bitwarden documentation.
* [GurpreetKang](https://github.com/GurpreetKang) for the code base - [BitwardenDecrypt](https://github.com/GurpreetKang/BitwardenDecrypt)
* [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/BitwardenDecryptBrute) for allowing my fork of the fork.
