package app.security.checkurl.service;

import app.security.secondFilter.filter.SecurityAnalyzer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;

@Service
public class PhishingCheckService {

    @Value("${google.safebrowsing.api-key}")
    private String apiKey;

    private final String GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=";

    private final RestTemplate restTemplate;

    public PhishingCheckService() {
        this.restTemplate = new RestTemplate();
    }

    public String isPhishingUrl(String url) {
        String apiUrl = GOOGLE_SAFE_BROWSING_URL + apiKey;

        // Google API 요청 형식에 맞춘 JSON 데이터
        String requestJson = "{ \"client\": { \"clientId\": \"your-app\", \"clientVersion\": \"1.0\" }, \"threatInfo\": { \"threatTypes\": [\"MALWARE\", \"SOCIAL_ENGINEERING\"], \"platformTypes\": [\"ANY_PLATFORM\"], \"threatEntryTypes\": [\"URL\"], \"threatEntries\": [{ \"url\": \"" + url + "\" }] } }";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> request = new HttpEntity<>(requestJson, headers);
        ResponseEntity<Map> response = restTemplate.exchange(apiUrl, HttpMethod.POST, request, Map.class);


        // 1차 필터: Google Safe Browsing 결과 검사
        boolean isPhishingByGoogle = response.getBody() != null && !response.getBody().isEmpty();

        // 2차 필터: SecurityAnalyzer 검사
        boolean isPhishingBySecondFilter = SecurityAnalyzer.secondFilter(url);

        // 3차 필터: APK 다운로드 차단 검사
        boolean isApkDownloadBlocked = SecurityAnalyzer.blockApkDownload(url);

        if (isPhishingByGoogle || isPhishingBySecondFilter) {
            return "🚨 피싱 사이트입니다! 🚨";
        } else if (isApkDownloadBlocked) {
            return "⚠️ APK 파일 다운로드가 차단되었습니다.";
        } else {
            return "✅ 안전한 사이트입니다.";
        }
    }
}
