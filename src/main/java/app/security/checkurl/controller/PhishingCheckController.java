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
    public ResponseEntity<String> checkUrl(@RequestBody Map<String, String> request) {
        String url = request.get("url");
        if (url == null || url.isEmpty()) {
            return ResponseEntity.badRequest().body("URL을 입력해주세요.");
        }

        boolean isPhishing = phishingCheckService.isPhishingUrl(url);

        if (isPhishing) {
            return ResponseEntity.ok("🚨 피싱 사이트입니다! 🚨");
        } else {
            return ResponseEntity.ok("✅ 안전한 사이트입니다.");
        }
    }
}
