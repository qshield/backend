package app.security.secondFilter.headerList;

import java.util.Map;
import java.util.Set;

public class Header {

//헤더 검증을 위한 whitelist
    static public final Map<String, Set<String>> WHITELIST = Map.ofEntries(
        Map.entry("Server", Set.of("nginx", "Apache", "Cloudflare", "Microsoft-IIS/10.0", "GitHub.com", "AkamaiGHost", "AppleWebKit", "KakaoBot")),
        Map.entry("X-Powered-By", Set.of("PHP/7.4", ".NET", "Express", "Servlet/3.1", "Node.js", "ASP.NET")),

        //  콘텐츠 관련 헤더
        Map.entry("Content-Type", Set.of("text/html; charset=UTF-8", "application/json", "application/xml", "application/javascript")),
        Map.entry("Content-Encoding", Set.of("gzip", "deflate", "br")),
        Map.entry("Content-Language", Set.of("en-US", "ko-KR", "ja-JP", "zh-CN")),
        Map.entry("Cache-Control", Set.of("no-cache", "no-store", "must-revalidate", "private", "public")),

        //  보안 관련 헤더
        Map.entry("Strict-Transport-Security", Set.of("max-age=31536000; includeSubDomains; preload", "max-age=63072000")),
        Map.entry("X-Frame-Options", Set.of("DENY", "SAMEORIGIN")),
        Map.entry("X-Content-Type-Options", Set.of("nosniff")),
        Map.entry("Referrer-Policy", Set.of("no-referrer", "strict-origin-when-cross-origin", "same-origin", "strict-origin")),
        Map.entry("Content-Security-Policy", Set.of("default-src 'self'", "default-src *", "script-src 'self'"))

    );


}
