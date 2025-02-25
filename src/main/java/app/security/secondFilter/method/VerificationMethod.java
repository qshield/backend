package studio.aroundhub.qshield.filter;

import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.net.*;
import java.util.*;

import static studio.aroundhub.qshield.filter.Header.WHITELIST;

@Slf4j
public class VerificationMethod {

    // DNS 검사: 해당 도메인이 존재하는지 않하는지 확인
    public static boolean isDomainResolvable(String urlString) {
        try {
            URL url = new URL(urlString);
            InetAddress.getByName(url.getHost());
            //Dns 서버에 요청을 보내 해당 url의 ip 주소를 조회한다.
            //정상적인 도메인이라면 ip 주소를, 없는 도메인이라면 예외를 발생시킨다.
            return true; // 도메인 존재
        } catch (UnknownHostException e) {
            return false;
        } catch (MalformedURLException e) {
            return false;//예외가 발생한다는 것은 해당 도메인이 존재하지 않는 것
        }
    }

    // SSL 인증서 유효성을 검사하는 함수
   public static boolean isValidSSL(String urlString) {
        try {
            URL url = new URL(urlString);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.connect();//인증서가 올바르게 설정되지 않았다면 IO 예외 발생
            connection.getServerCertificates(); // 서버에서 제공하는 SSL 인증서 목록과 일치하지 않으면 예외 발생
            return true;//문제가 없는 경우
        } catch (IOException e) {
            return false;
        }

    }




    //응답 헤더와  WhiteList의 헤더와 비교하여 whitelist의 값에 없으면 점수를 추가하는 방식 30점을 넘어가면 이상한 url로 판단
    //기존에는 헤더 키 값도 whitelist에 없으면 점수를 추가했지만 사이트마다 보완 관련 header를 응답하는게 너무 달라서 pass
   public static boolean isSuspiciousHeaders(Map<String, List<String>> headers) {
        int riskScore = 0;
        for (String header : WHITELIST.keySet()) {
            if (headers.containsKey(header)) {
                List<String> values = headers.get(header);
                boolean isValid = values.stream()
                        .anyMatch(value -> WHITELIST.get(header).stream()
                                .anyMatch(whiteValue -> whiteValue.equalsIgnoreCase(value))
                        );
                if (!isValid) {
                    riskScore += 10; // 배열에 유효값이 없으면 점수 추가
                }
            }
        }
        if(riskScore>30)log.info("Header Score validation fail " + riskScore);

        return riskScore >40;
    }

  public  static boolean isSuspiciousRedirect(String originalUrl) throws IOException {
        Set<String> redirectChain = getRedirectChain(originalUrl); //헤더를 검증한 redirectionUrl List를 가지고 있음
        if(redirectChain.isEmpty()) {
            return true; //만약 비어 있다면 안에서 문제가 발생
        }
        String lastUrl = new ArrayList<>(redirectChain).get(redirectChain.size() - 1);//마지막 url 가져오기
        boolean verification = SecurityAnalyzer.secondFilter(lastUrl); //우선 헤더 검증 및 사이트 검증 부터 진행
        if(verification) {
            return true;//만약 검증에서 오류가 발생하면 밑에 검증도 필요 없음
        }

        //단축 경로 검증을 위한 List
        final List<String> SHORTENED_URL_SERVICES = List.of("bit.ly", "tinyurl.com", "t.co", "goo.gl");


        String originalDomain = getDomain(originalUrl); //original
        String redirectedDomain = getDomain(lastUrl);
        //마지막 Url만 검증한다.


            if (originalUrl.startsWith("https://") && lastUrl.startsWith("http://")) {
                return true;
            }

            //도메인 변경이 감지
            if (!originalDomain.equalsIgnoreCase(redirectedDomain)) {
                if (getLevenshteinDistance(originalDomain, redirectedDomain) <= 2) {
                    //google ->goog1e인지 판별
                    return true;
                }
            }
            //단축 URL감지
            if (SHORTENED_URL_SERVICES.contains(redirectedDomain)) {
                return true;
            }


        return false;
    }

   public static Set<String> getRedirectChain(String urlString) throws IOException {
        Set<String> redirectChain = new LinkedHashSet<>(); // 중복 방지 (순서 유지) ->중복이 발생하면 무한 루프 발생 가능
        URL url = new URL(urlString);
        int maxRedirects = 5; //  최대 허용 리디렉션 횟수 설정 -> 무한루프 방지를 위함

        while (maxRedirects > 0) { //  최대 리디렉션 횟수를 초과하면 종료
            maxRedirects--; // 매 루프마다 리디렉션 횟수 감소

            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            Map<String, List<String>> headers = connection.getHeaderFields();

            int status = connection.getResponseCode();
            if (status >= 300 && status < 400) {
                String redirectUrl = connection.getHeaderField("Location");

                if (redirectUrl == null || redirectUrl.isEmpty()) {
                    log.debug("redirectUrl is null or empty {}", connection.getURL());
                    return new LinkedHashSet<>();
                }


                if (!redirectUrl.startsWith("http")) {
                    redirectUrl = new URL(url, redirectUrl).toString(); // 상대 경로 → 절대 경로 변환
                }

                if (!redirectChain.contains(redirectUrl)) { //  중복된 리디렉션이 아니면 추가
                    redirectChain.add(redirectUrl);
                    url = new URL(redirectUrl); // 다음 URL로 이동
                } else {
                    log.debug(" redirection circulation: {}", redirectUrl);
                    return new LinkedHashSet<>();
                }
            } else {
                //마지막 redirection 지점
                redirectChain.add(connection.getURL().toString());
                connection.disconnect();
                break; // 리디렉션이 끝나면 종료
            }
        }

        if (maxRedirects == 0) {
            log.debug("redirection excess");
            return new LinkedHashSet<>();
        }

        return redirectChain; // 최종 리디렉션 경로 반환
    }



//유사 도메인 확인 검증 (google ->g00gle)
public   static int getLevenshteinDistance(String s1, String s2) {
        int[][] dp = new int[s1.length() + 1][s2.length() + 1];
        for (int i = 0; i <= s1.length(); i++) dp[i][0] = i;
        for (int j = 0; j <= s2.length(); j++) dp[0][j] = j;

        for (int i = 1; i <= s1.length(); i++) {
            for (int j = 1; j <= s2.length(); j++) {
                int cost = (s1.charAt(i - 1) == s2.charAt(j - 1)) ? 0 : 1;
                dp[i][j] = Math.min(Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1), dp[i - 1][j - 1] + cost);
            }
        }
        return dp[s1.length()][s2.length()];
    }

     static String getDomain(String urlString) {
        try {
            URL url = new URL(urlString);
            return url.getHost();
        } catch (Exception e) {
            return "";
        }
    }



}
