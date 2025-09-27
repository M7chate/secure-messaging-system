package mz.ujc.secure_messaging_system.controller;

import mz.ujc.secure_messaging_system.entity.Message;
import mz.ujc.secure_messaging_system.entity.User;
import mz.ujc.secure_messaging_system.service.MessageService;
import mz.ujc.secure_messaging_system.service.UserService;
import mz.ujc.secure_messaging_system.service.CryptoService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.util.Base64;

@Controller
public class MessageController {
    
    @Autowired
    private MessageService messageService;
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private SimpMessagingTemplate messagingTemplate;
    
    @Autowired
    private CryptoService cryptoService;
    
    @GetMapping("/chat/{recipientId}")
    public String chat(@PathVariable Long recipientId, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        User currentUser = userService.findByUsername(username).orElse(null);
        User recipient = userService.findById(recipientId).orElse(null);
        
        if (currentUser == null || recipient == null) {
            return "redirect:/dashboard";
        }
        
        List<Message> messages = messageService.getConversation(currentUser, recipient);
        
        // Descriptografar mensagens para exibição
        Map<Long, String> decryptedMessages = new HashMap<>();
        Map<Long, Map<String, String>> messageDetails = new HashMap<>();
        
        for (Message msg : messages) {
            try {
                if (msg.getReceiver().getId().equals(currentUser.getId())) {
                    String decrypted = messageService.decryptMessage(msg, currentUser);
                    decryptedMessages.put(msg.getId(), decrypted);
                    
                    // Adicionar detalhes da mensagem para debug
                    Map<String, String> details = new HashMap<>();
                    details.put("encryptedContent", msg.getEncryptedContent());
                    details.put("encryptedKey", msg.getSymmetricKeyEncrypted());
                    details.put("hash", msg.getContentHash());
                    details.put("signature", msg.getDigitalSignature());
                    messageDetails.put(msg.getId(), details);
                }
            } catch (Exception e) {
                decryptedMessages.put(msg.getId(), "[Erro ao descriptografar]");
            }
        }
        
        // Calcular chave DH compartilhada
        String dhSharedKey = cryptoService.calculateDHSharedKey(
            currentUser.getDhPrivateKey(), 
            recipient.getDhPublicKey()
        );
        
        model.addAttribute("currentUser", currentUser);
        model.addAttribute("recipient", recipient);
        model.addAttribute("messages", messages);
        model.addAttribute("decryptedMessages", decryptedMessages);
        model.addAttribute("messageDetails", messageDetails);
        model.addAttribute("dhSharedKey", dhSharedKey);
        
        return "chat/index";
    }
    
    @MessageMapping("/chat.sendMessage")
    public void sendMessage(@Payload Map<String, Object> messageData, Principal principal) {
        try {
            String senderUsername = principal.getName();
            User sender = userService.findByUsername(senderUsername).orElse(null);
            
            if (sender == null) return;
            
            Long recipientId = Long.parseLong(messageData.get("recipientId").toString());
            String content = messageData.get("content").toString();
            String type = messageData.getOrDefault("type", "TEXT").toString();
            
            User recipient = userService.findById(recipientId).orElse(null);
            if (recipient == null) return;
            
            Message.MessageType messageType = Message.MessageType.valueOf(type);
            Message savedMessage = messageService.sendMessage(sender, recipient, content, messageType);
            
            // Notificar destinatário via WebSocket
            Map<String, Object> notification = new HashMap<>();
            notification.put("messageId", savedMessage.getId());
            notification.put("senderId", sender.getId());
            notification.put("senderUsername", sender.getUsername());
            notification.put("content", content);
            notification.put("timestamp", savedMessage.getSentAt().toString());
            
            messagingTemplate.convertAndSendToUser(
                recipient.getUsername(),
                "/queue/messages",
                notification
            );
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @PostMapping("/api/messages/markRead/{messageId}")
    @ResponseBody
    public Map<String, Object> markAsRead(@PathVariable Long messageId) {
        Map<String, Object> response = new HashMap<>();
        try {
            messageService.markAsRead(messageId);
            response.put("success", true);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        return response;
    }
    
    @GetMapping("/api/chat/keyExchange/{recipientId}")
    @ResponseBody
    public Map<String, Object> getKeyExchangeInfo(@PathVariable Long recipientId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        User currentUser = userService.findByUsername(username).orElse(null);
        User recipient = userService.findById(recipientId).orElse(null);
        
        Map<String, Object> response = new HashMap<>();
        
        if (currentUser == null || recipient == null) {
            response.put("error", "Usuários não encontrados");
            return response;
        }
        
        try {
            // Calcular chave DH compartilhada
            String dhSharedKey = cryptoService.calculateDHSharedKey(
                currentUser.getDhPrivateKey(), 
                recipient.getDhPublicKey()
            );
            
            response.put("success", true);
            response.put("currentUser", Map.of(
                "username", currentUser.getUsername(),
                "dhPublicKey", currentUser.getDhPublicKey(),
                "rsaPublicKey", currentUser.getPublicKeyRSA()
            ));
            response.put("recipient", Map.of(
                "username", recipient.getUsername(),
                "dhPublicKey", recipient.getDhPublicKey(),
                "rsaPublicKey", recipient.getPublicKeyRSA()
            ));
            response.put("dhSharedKey", dhSharedKey);
            response.put("keyExchangeComplete", true);
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        
        return response;
    }
    @PostMapping("/api/upload/{recipientId}")
@ResponseBody
public Map<String, Object> uploadFile(@RequestParam("file") MultipartFile file,
                                     @PathVariable Long recipientId,
                                     Principal principal) {
    Map<String, Object> response = new HashMap<>();
    
    try {
        String senderUsername = principal.getName();
        User sender = userService.findByUsername(senderUsername).orElse(null);
        User recipient = userService.findById(recipientId).orElse(null);
        
        if (sender == null || recipient == null) {
            response.put("success", false);
            response.put("error", "Usuários não encontrados");
            return response;
        }
        
        if (file.isEmpty()) {
            response.put("success", false);
            response.put("error", "Arquivo vazio");
            return response;
        }
        
        // Verificar tamanho (10MB max)
        if (file.getSize() > 10 * 1024 * 1024) {
            response.put("success", false);
            response.put("error", "Arquivo muito grande. Máximo 10MB");
            return response;
        }
        
        // Converter arquivo para Base64
        String fileContent = Base64.getEncoder().encodeToString(file.getBytes());
        String fileName = file.getOriginalFilename();
        String contentType = file.getContentType();
        
        // Criar conteúdo da mensagem com metadados do arquivo
        String messageContent = String.format("FILE:%s:%s:%d:%s", 
            fileName, contentType, file.getSize(), fileContent);
        
        // Determinar tipo da mensagem
        Message.MessageType messageType = Message.MessageType.FILE;
        if (contentType != null && contentType.startsWith("image/")) {
            messageType = Message.MessageType.IMAGE;
        }
        
        // Enviar mensagem
        Message savedMessage = messageService.sendMessage(sender, recipient, messageContent, messageType);
        savedMessage.setFileName(fileName);
        savedMessage.setFileSize(file.getSize());
        messageService.updateMessage(savedMessage);
        
        // Notificar via WebSocket
        Map<String, Object> notification = new HashMap<>();
        notification.put("messageId", savedMessage.getId());
        notification.put("senderId", sender.getId());
        notification.put("senderUsername", sender.getUsername());
        notification.put("content", fileName + " (" + formatFileSize(file.getSize()) + ")");
        notification.put("type", messageType.toString());
        notification.put("fileName", fileName);
        notification.put("fileSize", file.getSize());
        notification.put("timestamp", savedMessage.getSentAt().toString());
        
        messagingTemplate.convertAndSendToUser(
            recipient.getUsername(),
            "/queue/messages",
            notification
        );
        
        response.put("success", true);
        response.put("messageId", savedMessage.getId());
        response.put("fileName", fileName);
        
    } catch (IOException e) {
        response.put("success", false);
        response.put("error", "Erro ao processar arquivo: " + e.getMessage());
    } catch (Exception e) {
        response.put("success", false);
        response.put("error", "Erro interno: " + e.getMessage());
        e.printStackTrace(); // Para debug
    }
    
    return response;
}

@GetMapping("/api/download/{messageId}")
public ResponseEntity<ByteArrayResource> downloadFile(@PathVariable Long messageId, Principal principal) {
    try {
        String username = principal.getName();
        User currentUser = userService.findByUsername(username).orElse(null);
        
        Message message = messageService.findById(messageId);
        if (message == null) {
            return ResponseEntity.notFound().build();
        }
        
        // Verificar permissão
        if (!message.getSender().getId().equals(currentUser.getId()) && 
            !message.getReceiver().getId().equals(currentUser.getId())) {
            return ResponseEntity.status(403).build();
        }
        
        // Descriptografar mensagem
        String decryptedContent = messageService.decryptMessage(message, currentUser);
        
        // Extrair dados do arquivo
        if (!decryptedContent.startsWith("FILE:")) {
            return ResponseEntity.badRequest().build();
        }
        
        String[] parts = decryptedContent.split(":", 5);
        if (parts.length < 5) {
            return ResponseEntity.badRequest().build();
        }
        
        String fileName = parts[1];
        String contentType = parts[2];
        String fileContent = parts[4];
        
        // Decodificar Base64
        byte[] fileBytes = Base64.getDecoder().decode(fileContent);
        
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(contentType))
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
            .body(new ByteArrayResource(fileBytes));
            
    } catch (Exception e) {
        e.printStackTrace(); // Para debug
        return ResponseEntity.status(500).build();
    }
}

// Método auxiliar para formatar tamanho do arquivo
private String formatFileSize(long size) {
    if (size < 1024) return size + " B";
    if (size < 1024 * 1024) return String.format("%.1f KB", size / 1024.0);
    return String.format("%.1f MB", size / (1024.0 * 1024.0));
}
    
    @GetMapping("/api/messages/{messageId}/details")
    @ResponseBody
    public Map<String, Object> getMessageDetails(@PathVariable Long messageId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        User currentUser = userService.findByUsername(username).orElse(null);
        Map<String, Object> response = new HashMap<>();
        
        try {
            Message message = messageService.findById(messageId);
            if (message == null) {
                response.put("error", "Mensagem não encontrada");
                return response;
            }
            
            // Verificar se o usuário tem permissão para ver esta mensagem
            if (!message.getSender().getId().equals(currentUser.getId()) && 
                !message.getReceiver().getId().equals(currentUser.getId())) {
                response.put("error", "Sem permissão para ver esta mensagem");
                return response;
            }
            
            // Descriptografar se for o destinatário
            String decryptedContent = "";
            if (message.getReceiver().getId().equals(currentUser.getId())) {
                decryptedContent = messageService.decryptMessage(message, currentUser);
            } else {
                decryptedContent = "[Conteúdo criptografado - você é o remetente]";
            }
            
            response.put("success", true);
            response.put("messageId", message.getId());
            response.put("sender", message.getSender().getUsername());
            response.put("receiver", message.getReceiver().getUsername());
            response.put("originalContent", decryptedContent);
            response.put("encryptedContent", message.getEncryptedContent());
            response.put("encryptedSymmetricKey", message.getSymmetricKeyEncrypted());
            response.put("contentHash", message.getContentHash());
            response.put("digitalSignature", message.getDigitalSignature());
            response.put("sentAt", message.getSentAt().toString());
            response.put("isRead", message.getIsRead());
            
            // Verificar hash
            String calculatedHash = cryptoService.calculateSHA256(decryptedContent);
            response.put("hashVerification", calculatedHash.equals(message.getContentHash()));
            
            // Verificar assinatura
            boolean signatureValid = cryptoService.verifySignature(
                decryptedContent, 
                message.getDigitalSignature(), 
                message.getSender().getPublicKeyRSA()
            );
            response.put("signatureVerification", signatureValid);
            
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        
        return response;
    }
} 


