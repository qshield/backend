package app.security.declaration.service;

import app.security.declaration.domain.Report;
import app.security.declaration.repository.ReportRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Transactional
@RequiredArgsConstructor
@Service
public class ReportService {

    private final ReportRepository reportRepository;

    public String reportUrl(String url, String reportedBy) {
        if (reportRepository.existsByUrl(url)) {
            return "이미 신고된 URL입니다.";
        }

        Report report = Report.builder()
                .url(url)
                .reportedBy(reportedBy)
                .reportedAt(LocalDateTime.now())
                .build();
        reportRepository.save(report);
        return "신고가 접수되었습니다.";
    }
}
