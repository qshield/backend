package app.security.checkurl.service;

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

    public boolean isPhishingUrl(String url) {
        String apiUrl = GOOGLE_SAFE_BROWSING_URL + apiKey;

        // Google API 요청 형식에 맞춘 JSON 데이터
        String requestJson = "{ \"client\": { \"clientId\": \"your-app\", \"clientVersion\": \"1.0\" }, \"threatInfo\": { \"threatTypes\": [\"MALWARE\", \"SOCIAL_ENGINEERING\"], \"platformTypes\": [\"ANY_PLATFORM\"], \"threatEntryTypes\": [\"URL\"], \"threatEntries\": [{ \"url\": \"" + url + "\" }] } }";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> request = new HttpEntity<>(requestJson, headers);
        ResponseEntity<Map> response = restTemplate.exchange(apiUrl, HttpMethod.POST, request, Map.class);

        // API 응답이 비어 있으면 안전한 URL, 비어 있지 않으면 피싱 사이트
        return response.getBody() != null && !response.getBody().isEmpty();
    }
}
