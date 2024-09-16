# encryption
to compile:
```
g++ main.cpp base64.cpp -o encryption
```

usage:
```
encryption <decrypt|encrypt> [key] message
  key: optional in case of encryption but required for decryption (generates one randomly if it's missing)
```
