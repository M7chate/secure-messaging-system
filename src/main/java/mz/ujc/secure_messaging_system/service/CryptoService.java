package mz.ujc.secure_messaging_system.service;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


@Service
public class CryptoService {
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    private static final int RSA_KEY_SIZE = 1024;
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_ALGORITHM = "AES";
    private static final String HASH_ALGORITHM = "SHA-256";
    
    // DH Parameters (grupos padrão RFC)
    private static final BigInteger DH_P = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
    
    private static final BigInteger DH_G = BigInteger.valueOf(2);
    
    // Geração de chaves RSA
    public Map<String, String> generateRSAKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyGen.initialize(RSA_KEY_SIZE);
            KeyPair keyPair = keyGen.generateKeyPair();
            
            String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            
            Map<String, String> keys = new HashMap<>();
            keys.put("publicKey", publicKey);
            keys.put("privateKey", privateKey);
            
            return keys;
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar chaves RSA", e);
        }
    }
    
    // Geração de chaves Diffie-Hellman
    public Map<String, String> generateDHKeyPair() {
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            byte[] privateBytes = new byte[16]; // 128 bits PRNG
            random.nextBytes(privateBytes);
            
            BigInteger privateKey = new BigInteger(1, privateBytes);
            BigInteger publicKey = DH_G.modPow(privateKey, DH_P);
            
            Map<String, String> keys = new HashMap<>();
            keys.put("publicKey", Base64.getEncoder().encodeToString(publicKey.toByteArray()));
            keys.put("privateKey", Base64.getEncoder().encodeToString(privateKey.toByteArray()));
            
            return keys;
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar chaves DH", e);
        }
    }
    
    // Calcular chave compartilhada DH
    public String calculateDHSharedKey(String myPrivateKey, String otherPublicKey) {
        try {
            BigInteger privateKey = new BigInteger(Base64.getDecoder().decode(myPrivateKey));
            BigInteger publicKey = new BigInteger(Base64.getDecoder().decode(otherPublicKey));
            
            BigInteger sharedKey = publicKey.modPow(privateKey, DH_P);
            
            return Base64.getEncoder().encodeToString(sharedKey.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Erro ao calcular chave compartilhada DH", e);
        }
    }
    
    // Criptografia RSA
    public String encryptRSA(String data, String publicKeyStr) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(spec);
            
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Erro na criptografia RSA", e);
        }
    }
    
    // Descriptografia RSA
    public String decryptRSA(String encryptedData, String privateKeyStr) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(spec);
            
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            
            byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Erro na descriptografia RSA", e);
        }
    }
    
    // Geração de chave AES
    public String generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar chave AES", e);
        }
    }
    
    // Criptografia AES
    public String encryptAES(String data, String keyStr) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, AES_ALGORITHM);
            
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Erro na criptografia AES", e);
        }
    }
    
    // Descriptografia AES
    public String decryptAES(String encryptedData, String keyStr) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, AES_ALGORITHM);
            
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            
            byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Erro na descriptografia AES", e);
        }
    }
    
    // Hash SHA-256
    public String calculateSHA256(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hashBytes = digest.digest(data.getBytes());
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao calcular hash SHA-256", e);
        }
    }
    
    // Assinatura Digital
    public String signData(String data, String privateKeyStr) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(spec);
            
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data.getBytes());
            
            byte[] signatureBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao assinar dados", e);
        }
    }
    
    // Verificação de Assinatura Digital
    public boolean verifySignature(String data, String signatureStr, String publicKeyStr) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(spec);
            
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(data.getBytes());
            
            byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }
    
    // Criptografia estilo PGP (Híbrida: RSA + AES)
    public Map<String, String> encryptPGP(String message, String recipientPublicKey) {
        try {
            // Gerar chave simétrica AES
            String aesKey = generateAESKey();
            
            // Criptografar mensagem com AES
            String encryptedMessage = encryptAES(message, aesKey);
            
            // Criptografar chave AES com RSA
            String encryptedAESKey = encryptRSA(aesKey, recipientPublicKey);
            
            Map<String, String> result = new HashMap<>();
            result.put("encryptedMessage", encryptedMessage);
            result.put("encryptedKey", encryptedAESKey);
            
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Erro na criptografia PGP", e);
        }
    }
    
    // Descriptografia estilo PGP
    public String decryptPGP(String encryptedMessage, String encryptedAESKey, String recipientPrivateKey) {
        try {
            // Descriptografar chave AES com RSA
            String aesKey = decryptRSA(encryptedAESKey, recipientPrivateKey);
            
            // Descriptografar mensagem com AES
            return decryptAES(encryptedMessage, aesKey);
        } catch (Exception e) {
            throw new RuntimeException("Erro na descriptografia PGP", e);
        }
    }
}