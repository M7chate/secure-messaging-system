package mz.ujc.secure_messaging_system.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.LocalDateTime;
import java.util.Set;

@SuppressWarnings("unused")
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "Username é obrigatório")
    @Size(min = 3, max = 50, message = "Username deve ter entre 3 e 50 caracteres")
    @Column(unique = true)
    private String username;
    
    @Email(message = "Email deve ser válido")
    @NotBlank(message = "Email é obrigatório")
    @Column(unique = true)
    private String email;
    
    @NotBlank(message = "Password é obrigatória")
    @Size(min = 6, message = "Password deve ter pelo menos 6 caracteres")
    private String password;
    
    @Column(name = "public_key_rsa", columnDefinition = "TEXT")
    private String publicKeyRSA;
    
    @Column(name = "private_key_rsa", columnDefinition = "TEXT")
    private String privateKeyRSA;
    
    @Column(name = "dh_public_key", columnDefinition = "TEXT")
    private String dhPublicKey;
    
    @Column(name = "dh_private_key", columnDefinition = "TEXT")
    private String dhPrivateKey;
    
    @Column(name = "certificate", columnDefinition = "TEXT")
    private String certificate;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();
    
    @Column(name = "is_online")
    private Boolean isOnline = false;
    
    @Column(name = "last_seen")
    private LocalDateTime lastSeen;
    
    // Construtor padrão
    public User() {}
    
    // Construtor com parâmetros
    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }
    
    // Getters e Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public String getPublicKeyRSA() { return publicKeyRSA; }
    public void setPublicKeyRSA(String publicKeyRSA) { this.publicKeyRSA = publicKeyRSA; }
    
    public String getPrivateKeyRSA() { return privateKeyRSA; }
    public void setPrivateKeyRSA(String privateKeyRSA) { this.privateKeyRSA = privateKeyRSA; }
    
    public String getDhPublicKey() { return dhPublicKey; }
    public void setDhPublicKey(String dhPublicKey) { this.dhPublicKey = dhPublicKey; }
    
    public String getDhPrivateKey() { return dhPrivateKey; }
    public void setDhPrivateKey(String dhPrivateKey) { this.dhPrivateKey = dhPrivateKey; }
    
    public String getCertificate() { return certificate; }
    public void setCertificate(String certificate) { this.certificate = certificate; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public Boolean getIsOnline() { return isOnline; }
    public void setIsOnline(Boolean isOnline) { this.isOnline = isOnline; }
    
    public LocalDateTime getLastSeen() { return lastSeen; }
    public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }
}