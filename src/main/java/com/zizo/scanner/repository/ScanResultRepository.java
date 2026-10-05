package com.zizo.scanner.repository;

import com.zizo.scanner.model.ScanResult;
import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.List;

@ApplicationScoped
public class ScanResultRepository implements PanacheRepository<ScanResult> {

    public List<ScanResult> lastNForUrl(String url, int n) {
        return find("url = ?1 order by scanDate desc", url)
                .page(0, n)
                .list();
    }

    public List<String> allTrackedUrls() {
        return getEntityManager()
                .createQuery("select distinct s.url from ScanResult s", String.class)
                .getResultList();
    }
}
