package com.zizo.scanner.scheduler;

import com.zizo.scanner.model.ScanResult;
import com.zizo.scanner.repository.ScanResultRepository;
import com.zizo.scanner.service.ScanService;
import io.quarkus.logging.Log;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;

@ApplicationScoped
public class ScanScheduler {

    @Inject
    ScanService scanService;

    @Inject
    ScanResultRepository scanResultRepository;

    // Toutes les 24h : relance un scan pour chaque URL déjà suivie
    @Scheduled(every = "24h")
    void rescanAllTrackedSites() {
        List<String> urls = scanResultRepository.allTrackedUrls();
        Log.infof("Scan planifié : %d site(s) à revérifier", urls.size());

        for (String url : urls) {
            try {
                List<ScanResult> previous = scanResultRepository.lastNForUrl(url, 1);
                int previousScore = previous.isEmpty() ? -1 : previous.get(0).score;

                ScanResult fresh = scanService.scan(url, previous.isEmpty() ? null : previous.get(0).owner);

                if (previousScore != -1 && fresh.score < previousScore - 10) {
                    alertScoreDrop(url, previousScore, fresh.score);
                }
            } catch (Exception e) {
                Log.errorf("Échec du rescan pour %s : %s", url, e.getMessage());
            }
        }
    }

    private void alertScoreDrop(String url, int oldScore, int newScore) {
        // Ici : brancher Quarkus Mailer ou un webhook Slack/Discord.
        // Volontairement en log pour rester simple à démontrer en soutenance.
        Log.warnf("ALERTE — Le score de %s est passé de %d à %d", url, oldScore, newScore);
    }
}
