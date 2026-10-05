package com.zizo.scanner.service;

import com.zizo.scanner.model.ScanResult;
import com.zizo.scanner.model.User;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import javax.net.ssl.HttpsURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class ScanService {

    // Header -> (poids dans le score, description pour le rapport)
    private static final Map<String, HeaderInfo> SECURITY_HEADERS = new LinkedHashMap<>();
    static {
        SECURITY_HEADERS.put("Content-Security-Policy", new HeaderInfo(25,
                "Empêche l'exécution de scripts malveillants injectés (protection XSS)."));
        SECURITY_HEADERS.put("Strict-Transport-Security", new HeaderInfo(20,
                "Force le navigateur à toujours utiliser HTTPS pour ce domaine."));
        SECURITY_HEADERS.put("X-Frame-Options", new HeaderInfo(15,
                "Empêche l'affichage du site dans une iframe (protection clickjacking)."));
        SECURITY_HEADERS.put("X-Content-Type-Options", new HeaderInfo(10,
                "Empêche le navigateur de deviner le type MIME d'un fichier."));
        SECURITY_HEADERS.put("Referrer-Policy", new HeaderInfo(10,
                "Contrôle les informations de référent envoyées entre sites."));
        SECURITY_HEADERS.put("Permissions-Policy", new HeaderInfo(10,
                "Contrôle l'accès aux fonctionnalités du navigateur (caméra, micro, géoloc)."));
    }

    private static final int[] COMMON_PORTS = {21, 22, 25, 80, 443, 3306, 3389};

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @Transactional
    public ScanResult scan(String targetUrl, User owner) throws Exception {
        ScanResult result = new ScanResult();
        result.url = targetUrl;
        result.owner = owner;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .timeout(Duration.ofSeconds(8))
                .GET()
                .build();

        HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
        Map<String, java.util.List<String>> headers = response.headers().map();

        analyzeHeaders(result, headers);
        analyzeCookies(result, headers);
        analyzeHttps(result, targetUrl, response);
        analyzePorts(result, targetUrl);

        computeScore(result);
        result.persist();
        return result;
    }

    private void analyzeHeaders(ScanResult result, Map<String, List<String>> headers) {
        for (String headerName : SECURITY_HEADERS.keySet()) {
            boolean present = headers.keySet().stream()
                    .anyMatch(h -> h.equalsIgnoreCase(headerName));
            if (present) {
                result.presentHeaders.add(headerName);
            } else {
                result.missingHeaders.add(headerName);
            }
        }
    }

    private void analyzeCookies(ScanResult result, Map<String, List<String>> headers) {
        List<String> setCookieValues = headers.getOrDefault("set-cookie", List.of());
        if (setCookieValues.isEmpty()) {
            // pas de cookie = rien à durcir, on considère les 3 critères comme respectés
            result.cookiesSecure = true;
            result.cookiesHttpOnly = true;
            result.cookiesSameSite = true;
            return;
        }
        result.cookiesSecure = setCookieValues.stream()
                .allMatch(c -> c.toLowerCase().contains("secure"));
        result.cookiesHttpOnly = setCookieValues.stream()
                .allMatch(c -> c.toLowerCase().contains("httponly"));
        result.cookiesSameSite = setCookieValues.stream()
                .allMatch(c -> c.toLowerCase().contains("samesite"));
    }

    private void analyzeHttps(ScanResult result, String targetUrl, HttpResponse<Void> response) {
        result.usesHttps = targetUrl.startsWith("https://");
        result.redirectsHttpToHttps = false; // affiné plus bas si on scanne la version http

        if (!result.usesHttps) {
            result.certificateValid = false;
            result.daysUntilCertExpiry = 0;
            return;
        }

        try {
            java.net.URL url = URI.create(targetUrl).toURL();
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.connect();
            X509Certificate cert = (X509Certificate) conn.getServerCertificates()[0];
            LocalDate expiry = cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            result.certificateValid = true;
            result.daysUntilCertExpiry = LocalDate.now().until(expiry).getDays()
                    + LocalDate.now().until(expiry).getMonths() * 30L
                    + LocalDate.now().until(expiry).getYears() * 365L;
            conn.disconnect();
        } catch (Exception e) {
            result.certificateValid = false;
            result.daysUntilCertExpiry = 0;
        }
    }

    private void analyzePorts(ScanResult result, String targetUrl) {
        String host;
        try {
            host = URI.create(targetUrl).getHost();
        } catch (Exception e) {
            return;
        }
        // scan passif, non intrusif : simple test de connexion TCP avec timeout court
        for (int port : COMMON_PORTS) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), 2000);
                result.presentHeaders.add("PORT_OUVERT:" + port); // stocké séparément dans une vraie version
            } catch (Exception ignored) {
                // port fermé/filtré, rien à signaler
            }
        }
    }

    private void computeScore(ScanResult result) {
        int total = 0;
        int max = SECURITY_HEADERS.values().stream().mapToInt(HeaderInfo::weight).sum();

        for (String header : result.presentHeaders) {
            HeaderInfo info = SECURITY_HEADERS.get(header);
            if (info != null) {
                total += info.weight();
            }
        }

        // bonus/malus HTTPS et cookies (10 pts chacun, hors barème headers)
        int bonusMax = 20;
        int bonus = 0;
        if (result.usesHttps && result.certificateValid) bonus += 10;
        if (result.cookiesSecure && result.cookiesHttpOnly && result.cookiesSameSite) bonus += 10;

        result.score = (int) Math.round(100.0 * (total + bonus) / (max + bonusMax));

        if (result.score < 40) result.riskLevel = ScanResult.RiskLevel.CRITIQUE;
        else if (result.score < 75) result.riskLevel = ScanResult.RiskLevel.MOYEN;
        else result.riskLevel = ScanResult.RiskLevel.BON;
    }

    public String descriptionFor(String headerName) {
        HeaderInfo info = SECURITY_HEADERS.get(headerName);
        return info != null ? info.description() : "";
    }

    private record HeaderInfo(int weight, String description) {
    }
}
