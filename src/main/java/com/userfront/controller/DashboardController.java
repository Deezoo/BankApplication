package com.userfront.controller;

import com.userfront.domain.User;
import com.userfront.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpSession;
import java.util.stream.Collectors;

@Controller
public class DashboardController {

    @Autowired
    UserRepository userRepository;

    @RequestMapping("/dashboard")
    public String displayDashboard(Model model, Authentication authentication, HttpSession httpSession) {
        //User user = userRepository.readByEmail(authentication.getName());
        User user = userRepository.readByEmail("mudi.lukman.developer@gmail.com");
        model.addAttribute("username", user.getUsername());
        //model.addAttribute("roles", authentication.getAuthorities().toString());
        model.addAttribute("roles", user.getUserRoles().stream().map(r -> r.getRole().getName()).collect(Collectors.joining(", ")));
        httpSession.setAttribute("loggedInUser", user);
        return "dashboard.html";
    }
}
