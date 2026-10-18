import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Locale;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class SecureAdditionClient {
    static final int MAX_FILE_SIZE = 10 * 1024 * 1024;
    private final String hostName;
    private final int port;

    public SecureAdditionClient(String hostName, int port) {
        this.hostName = hostName;
        this.port = port;
    }

    private SSLContext createContext() throws IOException, GeneralSecurityException {
        KeyStore keys = KeyStore.getInstance("JCEKS");
        try (InputStream file = Files.newInputStream(Path.of("client-keystore.ks"))) {
            keys.load(file, "clientkey-demo".toCharArray());
        }
        KeyStore trust = KeyStore.getInstance("JCEKS");
        try (InputStream file = Files.newInputStream(Path.of("client-truststore.ks"))) {
            trust.load(file, "clienttrust-demo".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keys, "clientkey-demo".toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }

    public void run() throws IOException, GeneralSecurityException {
        SSLContext context = createContext();
        BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            System.out.print("Operation (GET / PUT / DELETE / QUIT): ");
            String operation = console.readLine();
            if (operation == null || operation.trim().equalsIgnoreCase("QUIT")) {
                return;
            }
            operation = operation.trim().toUpperCase(Locale.ROOT);
            if (!operation.equals("GET") && !operation.equals("PUT") && !operation.equals("DELETE")) {
                System.out.println("Choose GET, PUT, DELETE, or QUIT.");
                continue;
            }
            System.out.print("Filename (PUT reads from this client folder): ");
            String name = console.readLine();
            if (name == null) {
                return;
            }
            try {
                // The server checks independently; this also protects local file paths.
                if (!name.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,99}") || name.endsWith(".")
                        || name.matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\\..*)?")) {
                    throw new IllegalArgumentException("Use a simple filename, such as notes.txt");
                }
                execute(context, operation, name);
            } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
                System.err.println("Operation failed: " + (e.getMessage() == null
                        ? "Connection ended before completion." : e.getMessage()));
            }
        }
    }

    private void execute(SSLContext context, String operation, String name)
            throws IOException, GeneralSecurityException {
        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(hostName, port)) {
            socket.setSoTimeout(15_000);
            socket.setEnabledProtocols(new String[] { "TLSv1.3" });
            socket.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS"); // Checks the hostname; not HTTP traffic.
            socket.setSSLParameters(parameters);
            socket.startHandshake();
            SSLSession session = socket.getSession();
            ((X509Certificate) session.getPeerCertificates()[0]).checkValidity();
            System.out.println(session.getProtocol() + " / " + session.getCipherSuite()
                    + " / server: " + session.getPeerPrincipal());
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            switch (operation) {
                case "GET": download(name, in, out); break;
                case "PUT": upload(name, in, out); break;
                case "DELETE":
                    out.writeUTF("DELETE");
                    out.writeUTF(name);
                    out.flush();
                    expectStatus(in, "OK");
                    System.out.println("Deleted server file: " + name);
                    break;
            }
        }
    }

    private void download(String name, DataInputStream in, DataOutputStream out) throws IOException {
        Path destination = Path.of("downloads", name);
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Download destination already exists: " + destination);
        }
        out.writeUTF("GET");
        out.writeUTF(name);
        out.flush();
        expectStatus(in, "OK");
        long size = in.readLong();
        if (size < 0 || size > MAX_FILE_SIZE) {
            throw new IOException("Invalid download length: " + size);
        }
        byte[] data = new byte[(int) size];
        in.readFully(data); // Receive everything before creating the local file.
        Files.createDirectories(destination.getParent());
        Files.write(destination, data, StandardOpenOption.CREATE_NEW);
        System.out.println("Downloaded " + size + " bytes to " + destination);
    }

    private void upload(String name, DataInputStream in, DataOutputStream out) throws IOException {
        Path source = Path.of(name);
        if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Upload source must be an existing regular file in the client folder");
        }
        byte[] data;
        try (InputStream file = Files.newInputStream(source, LinkOption.NOFOLLOW_LINKS)) {
            data = file.readNBytes(MAX_FILE_SIZE + 1);
        }
        if (data.length > MAX_FILE_SIZE) {
            throw new IOException("File exceeds the 10 MiB limit");
        }
        out.writeUTF("PUT");
        out.writeUTF(name);
        out.writeLong(data.length);
        out.flush();
        expectStatus(in, "READY");
        out.write(data);
        out.flush();
        expectStatus(in, "OK");
        System.out.println("Uploaded " + data.length + " bytes as " + name);
    }

    private void expectStatus(DataInputStream in, String expected) throws IOException {
        String status = in.readUTF();
        if (status.equals("ERROR")) {
            throw new IOException("Server rejected the request: " + in.readUTF());
        }
        if (!status.equals(expected)) {
            throw new IOException("Expected " + expected + ", received " + status);
        }
    }

    public static void main(String[] args) {
        try {
            if (args.length > 2) {
                throw new IllegalArgumentException("Usage: java SecureAdditionClient [port [host]]");
            }
            
            int port = args.length == 0 ? 8189 : Integer.parseInt(args[0]);
            
            String host = args.length < 2 ? "localhost" : args[1];
            new SecureAdditionClient(host, port).run();
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            System.err.println("Client failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
