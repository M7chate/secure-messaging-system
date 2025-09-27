package mz.ujc.secure_messaging_system.service;


import mz.ujc.secure_messaging_system.entity.User;
import mz.ujc.secure_messaging_system.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private CryptoService cryptoService;
    
    public User registerUser(String username, String email, String password) {
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Username já existe");
        }
        
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email já está registrado");
        }
        
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        
        // Gerar chaves RSA
        Map<String, String> rsaKeys = cryptoService.generateRSAKeyPair();
        user.setPublicKeyRSA(rsaKeys.get("publicKey"));
        user.setPrivateKeyRSA(rsaKeys.get("privateKey"));
        
        // Gerar chaves DH
        Map<String, String> dhKeys = cryptoService.generateDHKeyPair();
        user.setDhPublicKey(dhKeys.get("publicKey"));
        user.setDhPrivateKey(dhKeys.get("privateKey"));
        
        // Gerar certificado autoassinado simples
        String certificate = generateSelfSignedCertificate(user);
        user.setCertificate(certificate);
        
        return userRepository.save(user);
    }
    
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }
    
    public List<User> findAllExceptCurrent(Long currentUserId) {
        return userRepository.findAllExceptCurrent(currentUserId);
    }
    
    public List<User> findOnlineUsers(Long currentUserId) {
        return userRepository.findOnlineUsers(currentUserId);
    }
    
    public void setUserOnlineStatus(Long userId, boolean isOnline) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setIsOnline(isOnline);
            user.setLastSeen(LocalDateTime.now());
            userRepository.save(user);
        }
    }
    
    private String generateSelfSignedCertificate(User user) {
        // Implementação simples de certificado autoassinado
        // Em produção, usar bibliotecas como Bouncy Castle para certificados X.509 completos
        String certData = "BEGIN CERTIFICATE\n" +
                         "Subject: CN=" + user.getUsername() + ", Email=" + user.getEmail() + "\n" +
                         "PublicKey: " + user.getPublicKeyRSA() + "\n" +
                         "IssuedAt: " + LocalDateTime.now() + "\n" +
                         "END CERTIFICATE";
        
        // Assinar o certificado com a própria chave privada
        String signature = cryptoService.signData(certData, user.getPrivateKeyRSA());
        
        return certData + "\nSignature: " + signature;
    }
    
    public boolean validateCertificate(User user) {
        try {
            String certificate = user.getCertificate();
            String[] parts = certificate.split("\nSignature: ");
            if (parts.length != 2) return false;
            
            String certData = parts[0];
            String signature = parts[1];
            
            return cryptoService.verifySignature(certData, signature, user.getPublicKeyRSA());
        } catch (Exception e) {
            return false;
        }
    }
}

