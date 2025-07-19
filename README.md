# Catamorph

Basic usage (append a 16-byte random key, compute MD5, no version‐replace):

bash```
./patcher -in=original_binary -out=patched_binary
```


Overwrite Go version (auto-pad/truncate) and then append a key:

bash```
./catamorphic -in original_binary -out patched_binary -replace-ver "go1.12.20" -backup
```

If the original version was, say, "go1.17.7" (8 bytes), this will:

Pad "go1.12.20" to 8 bytes (it’s 9 bytes—so it gets truncated to "go1.12.2"), or

If you specify a shorter string (e.g. "go1.15" → 6 bytes), it pads with two \0 bytes to meet 8 bytes.

Always safe: the code never shifts subsequent bytes in the binary.

Overwrite version and inject at a custom offset:

bash```
./catamorphic -in original_binary -out patched_binary -replace-ver "go1.14.3" -offset 1024 -keylen 32 -hash sha256
```

This overwrites the detected Go‐version slot with "go1.14.3" (auto-padded/truncated as needed).

Then it overwrites 32 bytes at file offset 1024 (instead of appending).

Finally, it writes the output and prints the new SHA-256 hash.


> Example for ligolog-agent using signature replacement file.

bash```
..\catamorphic-v32.exe -in ".\ligolo-agent.exe" -out "testcase-v29.exe" --replace-ver "go5.66.6" -sig-file "..\signatures.json"
```