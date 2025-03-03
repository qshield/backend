package app.security.checkurl.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import app.security.checkurl.service.PhishingCheckService;

@RestController
@RequestMapping("/api")
public class PhishingCheckController {

    private final PhishingCheckService phishingCheckService;

    public PhishingCheckController(PhishingCheckService phishingCheckService) {
        this.phishingCheckService = phishingCheckService;
    }

    @PostMapping("/check-url")
    public ResponseEntity<Integer> checkUrl(@RequestBody Map<String, String> request) {
        String url = request.get("url");
        if (url == null || url.isEmpty()) {
            return ResponseEntity.badRequest().body(3);
        }

        int isPhishing = phishingCheckService.isPhishingUrl(url);
        return ResponseEntity.ok(isPhishing);
    }
}
