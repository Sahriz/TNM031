import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class SecureAdditionServer {
    static final int MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MiB: files fit in memory.
    private final int port;

    SecureAdditionServer(int port) {
        this.port = port;
    }

    // Same setup as the course example: stores -> managers -> SSLContext.
    private SSLContext createContext() throws IOException, GeneralSecurityException {
        KeyStore keys = KeyStore.getInstance("JCEKS");
        try (InputStream file = Files.newInputStream(Path.of("server-keystore.ks"))) {
            keys.load(file, "serverkey-demo".toCharArray());
        }
        KeyStore trust = KeyStore.getInstance("JCEKS");
        try (InputStream file = Files.newInputStream(Path.of("server-truststore.ks"))) {
            trust.load(file, "servertrust-demo".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keys, "serverkey-demo".toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }

    public void run() throws IOException, GeneralSecurityException {
        SSLContext context = createContext();
        Path root = Files.createDirectories(Path.of("files")).toRealPath();
        try (SSLServerSocket listener = (SSLServerSocket)
                context.getServerSocketFactory().createServerSocket(port)) {
            listener.setEnabledProtocols(new String[] { "TLSv1.3" });
            listener.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
            listener.setNeedClientAuth(true); // Client must present a trusted certificate.
            System.out.println("Secure file server listening on port " + port);
            System.out.println("File directory: " + root);

            // One operation per connection. A failed client does not stop the server.
            while (true) {
                try (SSLSocket socket = (SSLSocket) listener.accept()) {
                    socket.setSoTimeout(15_000);
                    socket.startHandshake();
                    SSLSession session = socket.getSession();
                    // Also check dates when the peer certificate is directly trusted.
                    ((X509Certificate) session.getPeerCertificates()[0]).checkValidity();
                    System.out.println(session.getProtocol() + " / " + session.getCipherSuite()
                            + " / client: " + session.getPeerPrincipal());
                    DataInputStream in = new DataInputStream(socket.getInputStream());
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    handleRequest(in, out, root);
                } catch (IOException | GeneralSecurityException e) {
                    System.err.println("Client connection failed: " + e.getMessage());
                }
            }
        }
    }

    private void handleRequest(DataInputStream in, DataOutputStream out, Path root)
            throws IOException {
        String operation = in.readUTF();
        if (!operation.equals("GET") && !operation.equals("PUT") && !operation.equals("DELETE")) {
            sendError(out, "BAD_COMMAND");
            return;
        }
        String name = in.readUTF();
        // Only basenames: no paths, Windows device names, or alternate data streams.
        if (!name.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,99}") || name.endsWith(".")
                || name.matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\\..*)?")) {
            sendError(out, "BAD_NAME");
            return;
        }
        Path file = root.resolve(name);
        if (Files.isSymbolicLink(file)) {
            sendError(out, "BAD_NAME");
            return;
        }
        if (!operation.equals("PUT")) {
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                sendError(out, "NOT_FOUND");
                return;
            }
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                sendError(out, "BAD_NAME");
                return;
            }
        }
        switch (operation) {
            case "GET": download(file, out); break;
            case "PUT": upload(file, in, out); break;
            case "DELETE":
                Files.delete(file);
                out.writeUTF("OK");
                out.flush();
                break;
        }
    }

    private void download(Path file, DataOutputStream out) throws IOException {
        byte[] data;
        try (InputStream source = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            // One extra byte lets us detect oversize files without loading all of them.
            data = source.readNBytes(MAX_FILE_SIZE + 1);
        }
        if (data.length > MAX_FILE_SIZE) {
            sendError(out, "TOO_LARGE");
            return;
        }
        out.writeUTF("OK");
        out.writeLong(data.length);
        out.write(data);
        out.flush();
    }

    private void upload(Path file, DataInputStream in, DataOutputStream out) throws IOException {
        long size = in.readLong();
        if (size < 0 || size > MAX_FILE_SIZE) {
            sendError(out, "BAD_SIZE");
            return;
        }
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            sendError(out, "ALREADY_EXISTS");
            return;
        }
        out.writeUTF("READY");
        out.flush();
        byte[] data = new byte[(int) size]; // The size check makes this cast/allocation safe.
        in.readFully(data); // Loops until all bytes arrive; throws if the connection ends early.
        Files.write(file, data, StandardOpenOption.CREATE_NEW); // Never replace an existing file.
        out.writeUTF("OK"); // Sent only after receiving and saving the complete file.
        out.flush();
    }

    private void sendError(DataOutputStream out, String reason) throws IOException {
        out.writeUTF("ERROR");
        out.writeUTF(reason);
        out.flush();
    }

    public static void main(String[] args) {
        try {
            if (args.length > 1) {
                throw new IllegalArgumentException("Usage: java SecureAdditionServer [port]");
            }
            int port = args.length == 0 ? 8189 : Integer.parseInt(args[0]);
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Port must be between 1 and 65535");
            }
            new SecureAdditionServer(port).run();
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            System.err.println("Server failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
