package app.security.declaration.controller;

import app.security.declaration.service.ReportService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api/reports")
@RequiredArgsConstructor
@RestController
public class ReportController {

    private final ReportService reportService;

    @PostMapping
    public ResponseEntity<String> reportUrl(String url, String reportedBy) {
        String response = reportService.reportUrl(url, reportedBy);
        return ResponseEntity.ok(response);
    }

}
