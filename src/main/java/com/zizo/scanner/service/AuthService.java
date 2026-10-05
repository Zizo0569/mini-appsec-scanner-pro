package com.zizo.scanner.service;

import com.zizo.scanner.model.User;
import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;
import org.mindrot.jbcrypt.BCrypt;

import java.time.Duration;
import java.util.Set;

@ApplicationScoped
public class AuthService {

    @Transactional
    public User register(String username, String rawPassword) {
        if (User.findByUsername(username) != null) {
            throw new IllegalArgumentException("Ce nom d'utilisateur existe déjà.");
        }
        User user = new User();
        user.username = username;
        user.passwordHash = BCrypt.hashpw(rawPassword, BCrypt.gensalt(12));
        user.role = "USER";
        user.persist();
        return user;
    }

    public String login(String username, String rawPassword) {
        User user = User.findByUsername(username);
        if (user == null || !BCrypt.checkpw(rawPassword, user.passwordHash)) {
            throw new SecurityException("Identifiants invalides.");
        }
        return Jwt.issuer("mini-appsec-scanner")
                .upn(user.username)
                .groups(Set.of(user.role))
                .expiresIn(Duration.ofHours(8))
                .sign();
    }
}
