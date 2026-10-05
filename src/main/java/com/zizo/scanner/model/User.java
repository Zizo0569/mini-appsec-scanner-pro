package com.zizo.scanner.model;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

@Entity
@Table(name = "app_user")
public class User extends PanacheEntity {

    @Column(unique = true, nullable = false)
    public String username;

    @Column(nullable = false)
    public String passwordHash;

    // "USER" ou "ADMIN"
    @Column(nullable = false)
    public String role = "USER";

    public static User findByUsername(String username) {
        return find("username", username).firstResult();
    }
}
