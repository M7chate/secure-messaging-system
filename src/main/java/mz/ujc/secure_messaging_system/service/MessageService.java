package mz.ujc.secure_messaging_system.service;


import mz.ujc.secure_messaging_system.entity.Message;
import mz.ujc.secure_messaging_system.entity.User;
import mz.ujc.secure_messaging_system.repository.MessageRepository;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Map;
import java.util.Optional;


@Service
public class MessageService {
    
    @Autowired
    private MessageRepository messageRepository;
    
    @Autowired
    private CryptoService cryptoService;
    
    public Message sendMessage(User sender, User receiver, String content, Message.MessageType type) {
        try {
            // Calcular hash do conteúdo original
            String contentHash = cryptoService.calculateSHA256(content);
            
            // Criptografia PGP (RSA + AES)
            Map<String, String> encrypted = cryptoService.encryptPGP(content, receiver.getPublicKeyRSA());
            
            // Assinar mensagem
            String signature = cryptoService.signData(content, sender.getPrivateKeyRSA());
            
            Message message = new Message();
            message.setSender(sender);
            message.setReceiver(receiver);
            message.setEncryptedContent(encrypted.get("encryptedMessage"));
            message.setSymmetricKeyEncrypted(encrypted.get("encryptedKey"));
            message.setContentHash(contentHash);
            message.setDigitalSignature(signature);
            message.setMessageType(type);
            
            return messageRepository.save(message);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao enviar mensagem", e);
        }
    }
    
    public String decryptMessage(Message message, User receiver) {
        try {
            // Descriptografar mensagem usando PGP
            String decryptedContent = cryptoService.decryptPGP(
                message.getEncryptedContent(), 
                message.getSymmetricKeyEncrypted(), 
                receiver.getPrivateKeyRSA()
            );
            
            // Verificar integridade
            String calculatedHash = cryptoService.calculateSHA256(decryptedContent);
            if (!calculatedHash.equals(message.getContentHash())) {
                throw new RuntimeException("Integridade da mensagem comprometida");
            }
            
            // Verificar assinatura
            boolean signatureValid = cryptoService.verifySignature(
                decryptedContent, 
                message.getDigitalSignature(), 
                message.getSender().getPublicKeyRSA()
            );
            
            if (!signatureValid) {
                throw new RuntimeException("Assinatura digital inválida");
            }
            
            return decryptedContent;
        } catch (Exception e) {
            throw new RuntimeException("Erro ao descriptografar mensagem", e);
        }
    }
    
    public List<Message> getConversation(User user1, User user2) {
        return messageRepository.findConversation(user1, user2);
    }
    
    public void markAsRead(Long messageId) {
        messageRepository.findById(messageId).ifPresent(message -> {
            message.setIsRead(true);
            messageRepository.save(message);
        });
    }
    
    public long getUnreadMessageCount(User user) {
        return messageRepository.countUnreadMessages(user);
    }
    
    public Message findById(Long messageId) {
        Optional<Message> messageOpt = messageRepository.findById(messageId);
        return messageOpt.orElse(null);
    }
    // Adicione este método no MessageService:
    public Message updateMessage(Message message) {
    return messageRepository.save(message);
}
}