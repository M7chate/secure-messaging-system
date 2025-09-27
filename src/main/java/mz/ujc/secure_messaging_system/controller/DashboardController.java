package mz.ujc.secure_messaging_system.controller;

import mz.ujc.secure_messaging_system.entity.User;
import mz.ujc.secure_messaging_system.service.MessageService;
import mz.ujc.secure_messaging_system.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import java.util.List;

@Controller
@RequestMapping("/dashboard")
public class DashboardController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private MessageService messageService;
    
    @GetMapping
    public String dashboard(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth.getName();
        
        User currentUser = userService.findByUsername(username).orElse(null);
        if (currentUser == null) {
            return "redirect:/login";
        }
        
        // Marcar usuário como online
        userService.setUserOnlineStatus(currentUser.getId(), true);
        
        List<User> allUsers = userService.findAllExceptCurrent(currentUser.getId());
        List<User> onlineUsers = userService.findOnlineUsers(currentUser.getId());
        long unreadCount = messageService.getUnreadMessageCount(currentUser);
        
        model.addAttribute("currentUser", currentUser);
        model.addAttribute("allUsers", allUsers);
        model.addAttribute("onlineUsers", onlineUsers);
        model.addAttribute("unreadCount", unreadCount);
        
        return "dashboard/index";
    }
}