package app.security.secondFilter.filter;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import static app.security.secondFilter.method.VerificationMethod.*;


@Slf4j
public class SecurityAnalyzer {


    //2차 필터 true라면 문제가 있는 URL이라고 판단한다.

    /*
    현재 문제점 일부 정상적인 웹 사이트에서는 크롤링에 대한 제한을 하고 있기 때문에 403 응답 코드를 넘겨준다.
    하지만 크롤링의 경우 우회적인 방법으로 사용이 가능하나 나중에 문제가 발생할 수 있기 때문에 사용하지 않음
    대신 403 응답코드인데 Header 값을 정상적으로 받은 경우 이것을 가지고 검증
    1차 필터에서 BlackList Url을 필터링 했기 때문에 Header 값을 가지고 검증한다.
     */
    //2차 필터
    public static boolean secondFilter(String urlString) {
        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) { //Url에 형식 오류가 있으면 예외 발생
            log.debug("Url format Error: {}", urlString);
            return true; //위조 혹은 잘못된 Url이라고 판단한다.
        }

        HttpURLConnection connection = null;
        try {
            // 해당 도메인 자체가 존재하는지 확인한다.
            if (!isDomainResolvable(urlString)) {
                log.debug("Unknown Host: {}", urlString);
                return true;
            }

            connection = (HttpURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(false);
            //3xx 코드의 경우 redirection 방지
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            //실제 네트워크 연결은  header를 가져오는 상황 등에서 암묵적으로 연결된다.

            // 도메인 자체가 문제가 없다면 SSL 인증서를 확인한다.
            if (!isValidSSL(urlString)) {
                log.debug("SSL Certificate Error {}", urlString);
                return true; // SSL 문제가 있으면 위조 가능성 높음
            }

            int responseCode = connection.getResponseCode();
            Map<String, List<String>> headers = connection.getHeaderFields();

            // HTTP 응답 코드 검사
            if ( responseCode == 404 || responseCode == 500|| (responseCode == 403 &&headers.isEmpty())) {
                log.debug("Response Error: {} ({})", responseCode, urlString);
                return true; // 오류 응답 발생 시 위조 가능성 높음
            }


            boolean isHeaderSuspicious = isSuspiciousHeaders(headers);
            if (responseCode >= 300 && responseCode < 400) {
                String redirectedUrl = connection.getHeaderField("Location");

                if (redirectedUrl == null || redirectedUrl.isEmpty()) {
                    log.debug("Redirection Url not exist : {}", urlString);
                    return true;
                }

                if (isSuspiciousRedirect(urlString)) {
                    log.debug("External redirection : {} → {}", urlString, redirectedUrl);
                    return true;
                }
            }


            //헤더 값도 문제이고 403 응답 코드를 보낸다면 주의가 필요한 사이트로 판별한다.
            if (isHeaderSuspicious &&responseCode == 403)
            {
                log.debug(" Header value abnormal: {}", urlString);
                return true;
            }

            log.debug("Domain Validation Success: {}", urlString);
            return false;
        } catch (SocketTimeoutException e) {
            log.debug("Connection Timeout: {}", urlString);
            return true; // 응답이 일정시간 없으면 위험한 사이트라고 판단한다.
        } catch (IOException e) {
            log.debug("NetWork Error: {}", urlString);
            return true;
        } finally {
            if (connection != null) {
                connection.disconnect(); // 연결 해제
            }
        }
    }


    public static void main(String[] args) throws IOException {
        String[] normalUrls = {
                "https://www.naver.com", "https://www.coupang.com", "https://www.kakao.com",
                "https://www.daum.net", "https://www.saramin.co.kr", "https://www.wemakeprice.com",
                "https://www.jobkorea.co.kr", "https://www.baemin.com", "https://www.yanolja.com",
                "https://www.interpark.com", "https://www.gmarket.co.kr", "https://www.11st.co.kr",
                "https://www.ssg.com", "https://www.lotteon.com", "https://www.watcha.com",
                "https://www.clien.net", "https://www.ppomppu.co.kr", "https://www.inven.co.kr",
                "https://www.hancom.com", "https://www.genesis.com", "https://www.toss.im",
                "https://www.shinhan.com", "https://www.kbstar.com", "https://www.nhbank.com",
                "https://www.bok.or.kr", "https://www.kt.com", "https://www.sktelecom.com",
                "https://www.lguplus.com", "https://www.kisa.or.kr", "https://www.melon.com"
        };

        String[] phishingUrls = {
                "http://naver-secure-login.com", "https://coupang-account-verify.com",
                "http://kakao-security-check.com", "https://daum-account-recovery.net",
                "http://saramin-reset-verification.com", "https://wemakeprice-billing-update.com",
                "http://jobkorea-premium-support.com", "https://baemin-authentication-check.com",
                "http://yanolja-secure-login.net", "https://interpark-login-alert.com",
                "http://gmarket-premium-activation.com", "https://11st-streaming-check.com",
                "http://ssg-verification-support.com", "https://lotteon-login-security.com",
                "http://watcha-billing-auth.com", "https://clien-secure-verification.com",
                "http://ppomppu-driver-check.com", "https://inven-authentication-alert.com",
                "http://hancom-support-login.com", "https://genesis-billing-verification.com",
                "http://toss-driver-update.com", "https://shinhan-premium-support.com",
                "http://kbstar-secure-check.com", "https://nhbank-host-verification.com",
                "http://bok-travel-alert.com", "https://kt-security-update.com",
                "http://sktelecom-account-alert.com", "https://lguplus-business-auth.com",
                "http://kisa-premium-check.com", "https://melon-account-verification.com"
        };


        System.out.println("Normal Test");
        for (String url : normalUrls) {
            boolean forgery = secondFilter(url);
            System.out.println("URL: " + url + " : " + forgery);
        }


        System.out.println("Abnormal Test");
        for (String url :  phishingUrls) {
            boolean forgery = secondFilter(url);
            System.out.println("URL: " + url + " : " +forgery);
        }

    }

    public static boolean blockApkDownload(String url) {
        String lowerUrl = url.toLowerCase();

        // APK 파일 다운로드 패턴 검사
        return lowerUrl.endsWith(".apk") ||  // .apk로 끝나는 URL 차단
                lowerUrl.contains("/download/") && lowerUrl.contains(".apk") ||  // /download/ 디렉토리 안 APK 차단
                lowerUrl.matches(".*(\\?|&)file=.*\\.apk.*") ||  // file=example.apk 형태의 다운로드 차단
                lowerUrl.matches(".*(\\?|&)attachment=.*\\.apk.*") ||  // attachment=example.apk 형태의 다운로드 차단
                lowerUrl.matches(".*(\\?|&)filename=.*\\.apk.*") ||  // filename=example.apk 형태의 다운로드 차단
                lowerUrl.matches(".*(\\?|&)type=application/vnd.android.package-archive.*"); // APK MIME 타입 다운로드 차단
    }

}

