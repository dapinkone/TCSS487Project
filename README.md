# Implementing SHA-3 derived function KMACXOF256 function

Inspired by the NIST.SP.800-185 paper, Peter and Hyunggil collaborated to implement the cryptographic algorithm in Java.

# Usage

```java Main -[h|t|e|d] [-fin input] [-fout output] [-pw password]```

first flag(required) is for the mode:

- -h(ash)
- -t(ag)
- -e(ncrypt)
- -d(ecrypt)

optional flags:
- -fout output.file
  - file which is written to in binary. If no output file supplied, binary will be printed to screen in hex, or text output will be printed in ascii.
- -fin input.file
  - input file; if not provided, user will be requested to provide data via the command-line.
- -pw password
  - self explanatory. Password will be used for encryption, decryption and tag/MAC modes.