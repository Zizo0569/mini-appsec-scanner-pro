package com.zizo.scanner.model;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scan_result")
public class ScanResult extends PanacheEntity {

    @Column(nullable = false)
    public String url;

    @Column(nullable = false)
    public LocalDateTime scanDate = LocalDateTime.now();

    public int score;

    @ElementCollection
    @CollectionTable(name = "scan_present_headers", joinColumns = @jakarta.persistence.JoinColumn(name = "scan_id"))
    @Column(name = "header_name")
    public List<String> presentHeaders = new ArrayList<>();

    @ElementCollection
    @CollectionTable(name = "scan_missing_headers", joinColumns = @jakarta.persistence.JoinColumn(name = "scan_id"))
    @Column(name = "header_name")
    public List<String> missingHeaders = new ArrayList<>();

    public boolean usesHttps;
    public boolean redirectsHttpToHttps;
    public boolean certificateValid;
    public long daysUntilCertExpiry;

    public boolean cookiesSecure;
    public boolean cookiesHttpOnly;
    public boolean cookiesSameSite;

    @Enumerated(EnumType.STRING)
    public RiskLevel riskLevel;

    @ManyToOne
    public User owner;

    public enum RiskLevel {
        CRITIQUE, MOYEN, BON
    }

    public static List<ScanResult> historyForUrl(String url) {
        return list("url = ?1 order by scanDate desc", url);
    }
}
