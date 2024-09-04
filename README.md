# JA4L_Streamlit
A PoC JA4L application that attempts to estimate distance from the server using TTL and JA4 data. 


## Breakdown of a JA4L Fingerprint
- Version (ja4l_a): This is extracted from bytes 9 to 11 of the raw TLS data. It represents the TLS version used in the handshake.
- Random Field: The next 32 bytes (bytes 11 to 43) represent the random data used in the handshake.

### Sample JA4L Fingerprint

```Version: 771, Random: c2b3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9bacb00112233445566778899aabbcc```

### Explanation of the Sample:

- ```Version: 771```
  - The version number 771 corresponds to TLS version 1.2 (hexadecimal 0x0303).

- ```Random: c2b3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9bacb00112233445566778899aabbcc```
  - This is a 32-byte random string extracted from the handshake, represented in hexadecimal format.

### How This Fingerprint is Generated in the Code:

The ja4l_a value (771) is derived from:

```python
ja4l_a = int.from_bytes(raw_data[9:11], byteorder='big')
```

The random field is captured and formatted as follows:

```python
ja4l_fingerprint = f"Version: {ja4l_a}, Random: {raw_data[11:43].hex()}"
```
