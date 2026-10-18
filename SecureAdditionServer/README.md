# Lab 3 - Secure file transfer with Java TLS

The two original classes now upload, download, and delete files. The class names
`SecureAdditionServer` and `SecureAdditionClient` are retained from the course example.
There are no additional Java classes or external Java dependencies.

## Build and run

Use JDK 21 or later. Both `java` and `javac` must be available in your terminal.
From `C:\Projekt\TNM031\SecureAdditionServer`:

```powershell
javac -Xlint:all -d out server\SecureAdditionServer.java client\SecureAdditionClient.java
```

In **terminal A**, starting in that folder:

```powershell
cd server
java -cp ..\out SecureAdditionServer 8189
```

In **terminal B**, also starting in that folder:

```powershell
cd client
java -cp ..\out SecureAdditionClient 8189 localhost
```

The client has one menu: `GET`, `PUT`, `DELETE`, or `QUIT`, followed by a simple
filename such as `practice.txt`. Put upload files directly in the `client` folder.
Downloads go into `client/downloads`. The server uses only `server/files`.
Each operation opens a fresh TLS connection; the server handles one client at a time.
Store paths are relative to the process's working directory, so start each program
from its own folder as shown above. Port and hostname arguments remain optional.

### Demonstration

From the client folder, create a disposable file before starting the client:

```powershell
Set-Content -LiteralPath practice.txt -Value 'Lab 3 transfer test' -Encoding utf8
```

In the menu, enter `PUT`, then `practice.txt`. Next enter `GET`, then `practice.txt`.
Compare the original and downloaded copies in another terminal in the client folder:

```powershell
Get-FileHash -Algorithm SHA256 practice.txt
Get-FileHash -Algorithm SHA256 downloads\practice.txt
```

Finally enter `DELETE`, then `practice.txt`, to remove the server copy. Both client
copies remain. Enter `QUIT` to exit. Use a fresh name when repeating the demonstration;
existing destinations are protected from replacement. The menu reports errors and
lets you try another operation. One-shot commands and custom paths are no longer used.

## Certificates and stores

Fresh stores have been prepared locally for this implementation. Do not rerun setup
over them. On a new checkout without these files, run once from this folder:

```powershell
.\setup-stores.ps1
```

The script uses the handout's generate/export/import workflow with RSA-3072 keys,
SHA256withRSA certificates, and the same JCEKS format as the starter. It refuses to
replace existing identities. `keytool` must be on PATH. If generation fails midway,
inspect the error and the files it names before deciding which incomplete outputs to
replace; rerunning is intentionally not destructive.

| File, relative to this folder | Contents | Demo password |
| --- | --- | --- |
| `server/server-keystore.ks` | Server private key and certificate | `serverkey-demo` |
| `server/server-truststore.ks` | Trusted client certificate | `servertrust-demo` |
| `client/client-keystore.ks` | Client private key and certificate | `clientkey-demo` |
| `client/client-truststore.ks` | Trusted server certificate | `clienttrust-demo` |

The identity-store password also unlocks its private-key entry, matching `kmf.init`.
These are disposable lab passwords shown in the source and setup script, not a
production secret-management scheme. Generated credentials and transferred files are
excluded from Git. Never send the private keystore to the other peer; exchange the
exported public `.cer` file. The server certificate covers `localhost` and `127.0.0.1`.
To connect to another machine, generate a server certificate whose SAN contains its
actual hostname/IP and import that certificate into the client truststore.

Inspect an entry from this folder, supplying its password when prompted:

```powershell
keytool -list -v -storetype JCEKS -keystore server\server-keystore.ks
keytool -list -v -storetype JCEKS -keystore client\client-keystore.ks
keytool -list -v -storetype JCEKS -keystore server\server-truststore.ks
keytool -list -v -storetype JCEKS -keystore client\client-truststore.ks
```

Each keystore should have one `PrivateKeyEntry`; each truststore should have one
`trustedCertEntry` for the **other** peer. The two identity fingerprints must differ.
The old LIU starter files and the separate `lab3` folder are not used by this program.

## Connection to the course requirements

The lab PDF requires download, upload, and deletion by filename, plus six security
conditions. The textbook's `KeyStore -> KeyManagerFactory/TrustManagerFactory ->
SSLContext -> socket factory -> secure socket` sequence is retained in both files.

| PDF condition | Implementation |
| --- | --- |
| Data integrity | TLS authenticated encryption protects records; explicit byte counts reject incomplete transfers. |
| Encrypted file exchange | Headers, statuses, and file bytes all use the same `SSLSocket`. |
| Strong cryptography | Both ends require TLS 1.3 and `TLS_AES_128_GCM_SHA256`; identity keys are RSA-3072. |
| Distinct stores | Each process loads its own identity and its own peer truststore. |
| Client authenticates server | Its trust manager verifies the server certificate; endpoint identification checks the requested host. |
| Server authenticates client | `setNeedClientAuth(true)` requires a certificate accepted by the server trust manager before handling requests. |

After handshaking, each side also checks the peer leaf certificate's validity dates
and prints the actual TLS version, cipher suite, and peer identity. The client reports
an operation's success only after receiving the required server response.

The chosen authorization policy is that clients deliberately trusted by this dedicated
server truststore may perform all three operations. Do not replace the narrow truststore
with a broad CA store and assume every certificate it validates should have file access.

The chapter's addition example uses text lines. The file service uses
`DataInputStream`/`DataOutputStream` so it preserves binary bytes, Unicode text, and
blank lines without treating file content as command delimiters. This is an application
protocol layered over the same course TLS connection. It is not interoperable with an
ordinary FTP, FTPS, or SFTP client. The PDF does not prescribe that interoperability.

TLS 1.3, this binary message format, sequential clients, a 10 MiB limit, and the
no-overwrite rule are implementation choices, not extra requirements stated by the PDF.
The old chapter's RSA premaster-secret example describes an earlier handshake design;
JSSE implements the current TLS handshake for us. We do not write custom encryption.

## Protocol and method map

`UTF` means Java's length-prefixed modified UTF-8 (`writeUTF` / `readUTF`). It is used
only for short metadata, not file contents. `LONG` is an eight-byte signed length.

| Request | Successful exchange |
| --- | --- |
| `UTF(GET), UTF(name)` | Server sends `UTF(OK), LONG(length), bytes(length)`. |
| `UTF(DELETE), UTF(name)` | Server deletes the regular file, then sends `UTF(OK)`. |
| `UTF(PUT), UTF(name), LONG(length)` | Server sends `UTF(READY)`; client sends exactly `length` bytes; server saves the received bytes, then sends `UTF(OK)`. |

For a rejected request, the response is `UTF(ERROR), UTF(code)`. Codes include `BAD_COMMAND`,
`BAD_NAME`, `BAD_SIZE`, `NOT_FOUND`, `ALREADY_EXISTS`, `TOO_LARGE`.
Unexpected I/O errors abort the connection and are logged by the server; an error string must not be inserted
where the receiver expects file bytes.

- **Both `createContext`:** load identity and trust, then initialize the TLS context.
- **Server `run`:** require client authentication, accept connections, complete the
  handshake, then process a request. Connection failures do not stop the listener.
- **Server `handleRequest`:** validate the command and filename, then dispatch GET,
  PUT, or DELETE. It checks files stay within the dedicated folder.
- **Client `run` / `execute`:** read the menu choice, validate the filename, establish
  TLS with hostname verification, and dispatch the operation.
- **Both `download` / `upload`:** read or write file bytes and exchange statuses.
- **Client `expectStatus`:** distinguish readiness, completion, and server rejection.

## Why this version is simpler

Like the Lab 2 implementation, this version uses direct methods and byte arrays.
Each file fits in memory because both peers enforce a 10 MiB limit. Disk reads use
`readNBytes(MAX_FILE_SIZE + 1)` so even an oversized source is read only up to that
bound. The extra byte detects an oversized file. Network receivers validate the
declared length before allocation, then use `DataInputStream.readFully(data)`.
That method keeps reading until the array is full or throws on early EOF.

The complete transfer is received before `Files.write` creates the destination.
This removes the custom copy loop, file channels, temporary files, and transfer-state
flags. It uses memory proportional to the file size, so this is suitable for the
small files in this lab rather than arbitrary large transfers.

## Limits and failure behavior

- Files are at most 10 MiB. Empty files and arbitrary binary contents are supported.
- Remote names are 1-100 ASCII letters/digits/dots/dashes/underscores and start with
  a letter or digit. Paths, trailing dots, Windows device names, directories, and
  symbolic links are rejected. The short Windows checks keep names safe on this OS.
- `CREATE_NEW` prevents overwriting an existing upload or download destination.
- A network interruption while receiving a file creates no destination file: the
  bytes remain in memory until the receive completes. A disk-write failure or process
  termination during saving can leave a partial file; disk writes are not atomic.
- Read operations time out after 15 seconds of inactivity. This is not a total
  transfer deadline and does not bound blocked writes.
- The server folder must be controlled by the server. Do not modify served files
  concurrently from another program. This lab does not handle hostile local races.
- A lost final `OK` can make the client report failure after the server saved a file.
  Check the server before retrying; the no-overwrite rule protects the existing copy.
- TLS encrypts data in transit; saved files are not encrypted on disk.

## Demonstration checks

Use disposable files: upload -> download -> compare hashes -> delete. Repeat with an
empty file, multiline UTF-8 text, and a larger binary file.

Then demonstrate that a client without a trusted certificate cannot operate on files,
and a client with the wrong server trust/hostname refuses the connection. Use copies
of the stores and fresh JVMs for negative tests. Do not weaken the working trust
manager or disable hostname checking to make a failure disappear.

The PDF explicitly requires that you explain the implemented security. Read the
method map and be ready to distinguish private keys, public certificates, trust,
authentication, authorization, and the framing of file bytes.
