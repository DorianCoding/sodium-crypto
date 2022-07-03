# sodium-crypto
A namespace implementing Libsodium cryptography (https://doc.libsodium.org/) for php developers. It is a namespace composed of many classes to perform a/symetric (de)encryption as well a blockchain function to perform proof-of-work. This also implements a Passwordhash/verify function.

## How to install libsodium on PHP?
As of PHP 7.2, Sodium is installed by default in PHP, you just need to uncomment this line in php.ini configuration file.
```
extension=sodium
```
More infos here : https://www.php.net/manual/en/sodium.installation.php
