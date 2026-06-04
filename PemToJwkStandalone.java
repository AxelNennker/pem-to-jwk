import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;

/**
 * Converts PEM-encoded RSA/EC public or private keys to JSON Web Key (JWK) format.
 * Standalone version with no external dependencies.
 * Supports RFC 7517 (JWK) and RFC 7638 (JWK Thumbprint).
 */
public class PemToJwkStandalone {
    
    private static final String VERSION = "1.0.0";
    
    public static void main(String[] args) {
        try {
            Options options = parseArguments(args);
            
            if (options.showHelp) {
                printUsage();
                System.exit(0);
            }
            
            if (options.showVersion) {
                System.out.println("PemToJwk version " + VERSION);
                System.exit(0);
            }
            
            String pemContent = readInput(options.inputFile);
            Key key = parsePemKey(pemContent);
            String jwk = convertToJwk(key, options);
            writeOutput(jwk, options.outputFile);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }
    
    private static Options parseArguments(String[] args) {
        Options options = new Options();
        
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--input":
                case "-i":
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--input requires a filename");
                    }
                    options.inputFile = args[++i];
                    break;
                    
                case "--output":
                case "-o":
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--output requires a filename");
                    }
                    options.outputFile = args[++i];
                    break;
                    
                case "--kid":
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--kid requires a value");
                    }
                    options.kid = args[++i];
                    break;
                    
                case "--use":
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--use requires a value (sig or enc)");
                    }
                    options.use = args[++i];
                    if (!options.use.equals("sig") && !options.use.equals("enc")) {
                        throw new IllegalArgumentException("--use must be 'sig' or 'enc'");
                    }
                    break;
                    
                case "--alg":
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--alg requires a value");
                    }
                    options.alg = args[++i];
                    break;
                    
                case "--key-ops":
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--key-ops requires comma-separated values");
                    }
                    options.keyOps = Arrays.asList(args[++i].split(","));
                    break;
                    
                case "--help":
                case "-h":
                    options.showHelp = true;
                    break;
                    
                case "--version":
                case "-v":
                    options.showVersion = true;
                    break;
                    
                default:
                    throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }
        
        return options;
    }
    
    private static void printUsage() {
        System.out.println("PemToJwk - Convert PEM keys to JSON Web Key (JWK) format");
        System.out.println();
        System.out.println("Usage: java PemToJwkStandalone [OPTIONS]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --input, -i FILE    Read PEM key from FILE (default: stdin)");
        System.out.println("  --output, -o FILE   Write JWK to FILE (default: stdout)");
        System.out.println("  --kid VALUE         Set Key ID (default: RFC 7638 thumbprint)");
        System.out.println("  --use VALUE         Set 'use' parameter: 'sig' or 'enc'");
        System.out.println("  --alg VALUE         Set 'alg' parameter (e.g., RS256, ES256)");
        System.out.println("  --key-ops VALUES    Set 'key_ops' (comma-separated)");
        System.out.println("  --help, -h          Show this help message");
        System.out.println("  --version, -v       Show version information");
        System.out.println();
        System.out.println("Supported key types: RSA (public/private), EC (public/private)");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java PemToJwkStandalone --input key.pem --output key.jwk");
        System.out.println("  cat key.pem | java PemToJwkStandalone > key.jwk");
        System.out.println("  java PemToJwkStandalone -i key.pem --kid mykey --use sig");
    }
    
    private static String readInput(String inputFile) throws IOException {
        if (inputFile == null) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        } else {
            return new String(Files.readAllBytes(Paths.get(inputFile)), StandardCharsets.UTF_8);
        }
    }
    
    private static Key parsePemKey(String pemContent) throws Exception {
        pemContent = pemContent.trim();
        
        boolean isPrivate = pemContent.contains("BEGIN PRIVATE KEY") || 
                           pemContent.contains("BEGIN RSA PRIVATE KEY") ||
                           pemContent.contains("BEGIN EC PRIVATE KEY");
        
        String base64 = pemContent
            .replaceAll("-----BEGIN [A-Z ]+-----", "")
            .replaceAll("-----END [A-Z ]+-----", "")
            .replaceAll("\\s+", "");
        
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        
        KeyFactory keyFactory;
        
        if (isPrivate) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            
            try {
                keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePrivate(spec);
            } catch (Exception e) {
                keyFactory = KeyFactory.getInstance("EC");
                return keyFactory.generatePrivate(spec);
            }
        } else {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            
            try {
                keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePublic(spec);
            } catch (Exception e) {
                keyFactory = KeyFactory.getInstance("EC");
                return keyFactory.generatePublic(spec);
            }
        }
    }
    
    private static String convertToJwk(Key key, Options options) throws Exception {
        Map<String, Object> jwk = new LinkedHashMap<>();
        
        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaPublic = (RSAPublicKey) key;
            jwk.put("kty", "RSA");
            jwk.put("n", base64UrlEncode(rsaPublic.getModulus()));
            jwk.put("e", base64UrlEncode(rsaPublic.getPublicExponent()));
            
        } else if (key instanceof RSAPrivateKey) {
            RSAPrivateKey rsaPrivate = (RSAPrivateKey) key;
            jwk.put("kty", "RSA");
            jwk.put("n", base64UrlEncode(rsaPrivate.getModulus()));
            
            if (key instanceof RSAPrivateCrtKey) {
                RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) key;
                jwk.put("e", base64UrlEncode(crtKey.getPublicExponent()));
                jwk.put("d", base64UrlEncode(crtKey.getPrivateExponent()));
                jwk.put("p", base64UrlEncode(crtKey.getPrimeP()));
                jwk.put("q", base64UrlEncode(crtKey.getPrimeQ()));
                jwk.put("dp", base64UrlEncode(crtKey.getPrimeExponentP()));
                jwk.put("dq", base64UrlEncode(crtKey.getPrimeExponentQ()));
                jwk.put("qi", base64UrlEncode(crtKey.getCrtCoefficient()));
            } else {
                throw new IllegalArgumentException("RSA private key must be in CRT format");
            }
            
        } else if (key instanceof ECPublicKey) {
            ECPublicKey ecPublic = (ECPublicKey) key;
            jwk.put("kty", "EC");
            jwk.put("crv", getCurveName(ecPublic.getParams()));
            
            ECPoint point = ecPublic.getW();
            jwk.put("x", base64UrlEncode(point.getAffineX()));
            jwk.put("y", base64UrlEncode(point.getAffineY()));
            
        } else if (key instanceof ECPrivateKey) {
            throw new UnsupportedOperationException(
                "EC private key conversion requires public key information. " +
                "Please convert the corresponding EC public key instead."
            );
            
        } else {
            throw new IllegalArgumentException("Unsupported key type: " + key.getClass().getName());
        }
        
        // Calculate thumbprint for kid
        String kid;
        if (options.kid != null) {
            kid = options.kid;
        } else {
            kid = computeThumbprint(jwk);
        }
        jwk.put("kid", kid);
        
        // Add optional fields
        if (options.use != null) {
            jwk.put("use", options.use);
        }
        
        if (options.alg != null) {
            jwk.put("alg", options.alg);
        }
        
        if (options.keyOps != null && !options.keyOps.isEmpty()) {
            jwk.put("key_ops", options.keyOps);
        }
        
        return formatJson(jwk);
    }
    
    private static String getCurveName(ECParameterSpec params) {
        int fieldSize = ((java.security.spec.ECFieldFp) params.getCurve().getField()).getFieldSize();
        
        switch (fieldSize) {
            case 256:
                return "P-256";
            case 384:
                return "P-384";
            case 521:
                return "P-521";
            default:
                throw new IllegalArgumentException("Unsupported EC curve with field size: " + fieldSize);
        }
    }
    
    private static String base64UrlEncode(BigInteger value) {
        byte[] bytes = value.toByteArray();
        
        if (bytes[0] == 0 && bytes.length > 1) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    private static String computeThumbprint(Map<String, Object> jwk) throws Exception {
        // RFC 7638: JWK Thumbprint
        Map<String, Object> canonical = new LinkedHashMap<>();
        
        String kty = (String) jwk.get("kty");
        
        if ("RSA".equals(kty)) {
            canonical.put("e", jwk.get("e"));
            canonical.put("kty", kty);
            canonical.put("n", jwk.get("n"));
        } else if ("EC".equals(kty)) {
            canonical.put("crv", jwk.get("crv"));
            canonical.put("kty", kty);
            canonical.put("x", jwk.get("x"));
            canonical.put("y", jwk.get("y"));
        } else {
            throw new IllegalArgumentException("Unsupported key type for thumbprint: " + kty);
        }
        
        String canonicalJson = toMinimalJson(canonical);
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(canonicalJson.getBytes(StandardCharsets.UTF_8));
        
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
    
    private static void writeOutput(String jwk, String outputFile) throws IOException {
        if (outputFile == null) {
            System.out.println(jwk);
        } else {
            Files.write(Paths.get(outputFile), jwk.getBytes(StandardCharsets.UTF_8));
        }
    }
    
    private static String toMinimalJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append("\"").append(entry.getKey()).append("\":");
            Object value = entry.getValue();
            if (value instanceof String) {
                sb.append("\"").append(escapeJson((String) value)).append("\"");
            } else {
                sb.append(value);
            }
        }
        sb.append("}");
        return sb.toString();
    }
    
    private static String formatJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        
        int index = 0;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            sb.append("  \"").append(entry.getKey()).append("\": ");
            
            Object value = entry.getValue();
            if (value instanceof String) {
                sb.append("\"").append(escapeJson((String) value)).append("\"");
            } else if (value instanceof List) {
                sb.append("[");
                List<?> list = (List<?>) value;
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append("\"").append(list.get(i)).append("\"");
                }
                sb.append("]");
            } else {
                sb.append(value);
            }
            
            if (index < map.size() - 1) {
                sb.append(",");
            }
            sb.append("\n");
            index++;
        }
        
        sb.append("}");
        return sb.toString();
    }
    
    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
    
    private static class Options {
        String inputFile = null;
        String outputFile = null;
        String kid = null;
        String use = null;
        String alg = null;
        List<String> keyOps = null;
        boolean showHelp = false;
        boolean showVersion = false;
    }
}
