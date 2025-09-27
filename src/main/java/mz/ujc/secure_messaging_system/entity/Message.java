package mz.ujc.secure_messaging_system.entity;


import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "messages")
public class Message {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne
    @JoinColumn(name = "sender_id", nullable = false)
    private User sender;
    
    @ManyToOne
    @JoinColumn(name = "receiver_id", nullable = false)
    private User receiver;
    
    @Column(name = "encrypted_content", columnDefinition = "TEXT")
    private String encryptedContent;
    
    @Column(name = "content_hash")
    private String contentHash;
    
    @Column(name = "digital_signature", columnDefinition = "TEXT")
    private String digitalSignature;
    
    @Column(name = "symmetric_key_encrypted", columnDefinition = "TEXT")
    private String symmetricKeyEncrypted;
    
    @Column(name = "message_type")
    @Enumerated(EnumType.STRING)
    private MessageType messageType = MessageType.TEXT;
    
    @Column(name = "sent_at")
    private LocalDateTime sentAt = LocalDateTime.now();
    
    @Column(name = "is_read")
    private Boolean isRead = false;
    
    @Column(name = "file_name")
    private String fileName;
    
    @Column(name = "file_size")
    private Long fileSize;
    
    public enum MessageType {
        TEXT, IMAGE, FILE
    }
    
    // Construtor padrão
    public Message() {}
    
    // Construtor com parâmetros
    public Message(User sender, User receiver, String encryptedContent, String contentHash) {
        this.sender = sender;
        this.receiver = receiver;
        this.encryptedContent = encryptedContent;
        this.contentHash = contentHash;
    }
    
    // Getters e Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public User getSender() { return sender; }
    public void setSender(User sender) { this.sender = sender; }
    
    public User getReceiver() { return receiver; }
    public void setReceiver(User receiver) { this.receiver = receiver; }
    
    public String getEncryptedContent() { return encryptedContent; }
    public void setEncryptedContent(String encryptedContent) { this.encryptedContent = encryptedContent; }
    
    public String getContentHash() { return contentHash; }
    public void setContentHash(String contentHash) { this.contentHash = contentHash; }
    
    public String getDigitalSignature() { return digitalSignature; }
    public void setDigitalSignature(String digitalSignature) { this.digitalSignature = digitalSignature; }
    
    public String getSymmetricKeyEncrypted() { return symmetricKeyEncrypted; }
    public void setSymmetricKeyEncrypted(String symmetricKeyEncrypted) { this.symmetricKeyEncrypted = symmetricKeyEncrypted; }
    
    public MessageType getMessageType() { return messageType; }
    public void setMessageType(MessageType messageType) { this.messageType = messageType; }
    
    public LocalDateTime getSentAt() { return sentAt; }
    public void setSentAt(LocalDateTime sentAt) { this.sentAt = sentAt; }
    
    public Boolean getIsRead() { return isRead; }
    public void setIsRead(Boolean isRead) { this.isRead = isRead; }
    
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    
    public Long getFileSize() { return fileSize; }
    public void setFileSize(Long fileSize) { this.fileSize = fileSize; }

    
}
