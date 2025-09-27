package mz.ujc.secure_messaging_system.controller;


import mz.ujc.secure_messaging_system.service.CryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Controller
public class HomeController {

    @Autowired
    private CryptoService cryptoService;

    @GetMapping("/")
    public String home(Model model, HttpServletRequest request) {
        model.addAttribute("title", "Secure Messaging System - UEM 2025");
        model.addAttribute("isMobile", isMobileDevice(request));
        model.addAttribute("clientIP", getClientIp(request));
        model.addAttribute("serverTime", LocalDateTime.now());
        model.addAttribute("version", "1.0.0"); // Pode ser lido do pom.xml ou application.properties

        return "home"; // Corresponde ao home.html
    }

    private boolean isMobileDevice(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null && (userAgent.contains("Mobile") || userAgent.contains("Android") || userAgent.contains("iPhone"));
    }

    private String getClientIp(HttpServletRequest request) {
        String remoteAddr = "";
        if (request != null) {
            remoteAddr = request.getHeader("X-FORWARDED-FOR");
            if (remoteAddr == null || "".equals(remoteAddr)) {
                remoteAddr = request.getRemoteAddr();
            }
        }
        return remoteAddr;
    }

    @GetMapping("/api/public/device-info")
    @ResponseBody
    public Map<String, Object> getDeviceInfo(HttpServletRequest request) {
        Map<String, Object> info = new HashMap<>();
        String clientIP = getClientIp(request);
        info.put("serverIP", clientIP); // Usar o IP do cliente como referência para o servidor local
        info.put("isMobile", isMobileDevice(request));

        // Para simular URLs de acesso em rede local
        if (!"127.0.0.1".equals(clientIP) && !"0:0:0:0:0:0:0:1".equals(clientIP) && !"localhost".equals(clientIP)) {
            Map<String, String> accessUrls = new HashMap<>();
            int serverPort = request.getServerPort();
            String scheme = request.getScheme();
            accessUrls.put("pc", scheme + "://" + request.getServerName() + ":" + serverPort + "/");
            accessUrls.put("mobile", scheme + "://" + clientIP + ":" + serverPort + "/");
            info.put("accessUrls", accessUrls);
        } else {
            // Se estiver em localhost, fornecer um exemplo de IP local
            Map<String, String> accessUrls = new HashMap<>();
            int serverPort = request.getServerPort();
            String scheme = request.getScheme();
            accessUrls.put("pc", scheme + "://localhost:" + serverPort + "/");
            accessUrls.put("mobile", scheme + "://192.168.1.X:" + serverPort + "/"); // Exemplo de IP local
            info.put("accessUrls", accessUrls);
        }

        return info;
    }

    @PostMapping("/api/public/test-rsa")
    @ResponseBody
    public Map<String, Object> testRsa(@RequestBody Map<String, String> payload) {
        Map<String, Object> result = new HashMap<>();
        try {
            String originalMessage = payload.get("message");
            Map<String, String> keys = cryptoService.generateRSAKeyPair();
            String publicKey = keys.get("publicKey");
            String privateKey = keys.get("privateKey");

            String encrypted = cryptoService.encryptRSA(originalMessage, publicKey);
            String decrypted = cryptoService.decryptRSA(encrypted, privateKey);

            String signature = cryptoService.signData(originalMessage, privateKey);
            boolean signatureValid = cryptoService.verifySignature(originalMessage, signature, publicKey);

            result.put("success", true);
            result.put("originalMessage", originalMessage);
            result.put("encryptedMessage", encrypted);
            result.put("decryptedMessage", decrypted);
            result.put("signatureValid", signatureValid);
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    @PostMapping("/api/public/test-dh")
    @ResponseBody
    public Map<String, Object> testDh() {
        Map<String, Object> result = new HashMap<>();
        try {
            // Alice
            Map<String, String> aliceKeys = cryptoService.generateDHKeyPair();
            String alicePrivateKey = aliceKeys.get("privateKey");
            String alicePublicKey = aliceKeys.get("publicKey");

            // Bob
            Map<String, String> bobKeys = cryptoService.generateDHKeyPair();
            String bobPrivateKey = bobKeys.get("privateKey");
            String bobPublicKey = bobKeys.get("publicKey");

            // Shared secrets
            String aliceSharedKey = cryptoService.calculateDHSharedKey(alicePrivateKey, bobPublicKey);
            String bobSharedKey = cryptoService.calculateDHSharedKey(bobPrivateKey, alicePublicKey);

            result.put("success", true);
            result.put("aliceKey", aliceSharedKey);
            result.put("bobKey", bobSharedKey);
            result.put("keysMatch", aliceSharedKey.equals(bobSharedKey));
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }
}