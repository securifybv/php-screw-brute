# PHP Screw Brute

This script recovers/brute forces the key for PHP files protected with PHP Screw 
(https://github.com/Luavis/php-screw).

PHP Screw uses the length of the compressed file to determine the starting index into the 
(hardcoded) key. The 'encryption' works by first compressing the PHP file with ZLIB 
(level 1) and XORing it with the inverse of the bytes and the key. Because ZLIB has a 
fixed header and the start index is different for different files, it is possible to 
recover parts of the key. The remaining bytes can be brute forced. In generally, the more 
files you have the faster the recovering of the key will be. Naturally all the files must 
be protected with the same PHP Screw key. Given enough files, no brute forcing is 
required.

## Example usage:

```
$ ./php-screw-brute.py test/*.php
[+] Trying key:     ca fe ba be 0 0 be ef
[!] Recovered key:  ca fe ba be de ad be ef
[+] Deciphering files
[-] test/array.php
[-] test/example.php
[-] test/hello.php
```
