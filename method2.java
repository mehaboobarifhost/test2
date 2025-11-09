import okhttp3.*;
import okhttp3.JavaNetCookieJar;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.CookieStore;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Performs programmatic (API-based) login to Aprimo.
 * This class provides two distinct login flows:
 * 1. Hybrid UI Flow (getLoginCallbackUrl): A brittle, multi-step "screen scrape"
 * to get SESSION COOKIES for Selenium UI tests.
 * 2. ROP API Flow (getApiAccessToken): A stable, single-call API flow to get an
 * ACCESS TOKEN for RestAssured API tests.
 *
 * This class is stateful and must be instantiated for each login session.
 *
 * @author Your Name
 * @version 2.0.0
 */
public class AprimoLogin {

    // --- Class Members ---
    private final String username;
    private final String password;
    private final ProxyConfig proxyConfig;

    private CookieManager cookieManager;
    private String codeVerifier; // Used by UI flow
    private String state;        // Used by UI flow
    private HttpUrl authorizeCallbackUrl; // Used by UI flow

    // --- Constants ---
    private static final String BASE_URL = "https://company-sb1.aprimo.com";
    private static final String LOGIN_PATH = "/login/Account/Login";
    private static final String TOKEN_PATH = "/login/connect/token";
    private static final String CLIENT_ID = "MarketingOps";
    private static final String REDIRECT_URI = "https://company-sb1.aprimo.com/MarketingOps/oidc/signin-callback.html";
    private static final String SCOPE = "api ui openid api-internal legacy-api filestore-access";

    /**
     * Simple configuration class for proxy settings.
     */
    public static class ProxyConfig {
        final String host;
        final int port;
        final String username;
        final String password;

        /**
         * Creates a new ProxyConfig.
         * @param host Proxy host (e.g., "webproxy.yourcompany.com")
         * @param port Proxy port (e.g., 8080)
         * @param username Proxy username (or null if not needed)
         * @param password Proxy password (or null if not needed)
         */
        public ProxyConfig(String host, int port, String username, String password) {
            this.host = host;
            this.port = port;
            this.username = username;
            this.password = password;
        }
    }

    /**
     * Constructor for a standard login.
     *
     * @param username The user's username.
     * @param password The user's password.
     */
    public AprimoLogin(String username, String password) {
        this(username, password, null);
    }

    /**
     * Constructor for a login that requires a proxy.
     *
     * @param username The user's username.
     * @param password The user's password.
     * @param proxyConfig A ProxyConfig object with proxy details.
     */
    public AprimoLogin(String username, String password, ProxyConfig proxyConfig) {
        this.username = username;
        this.password = password;
        this.proxyConfig = proxyConfig;
        this.cookieManager = new CookieManager();
        this.cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
    }

    /**
     * [FOR UI TESTS]
     * Performs the brittle, multi-step "screen scrape" (Authorization Code) flow
     * to acquire the SESSION COOKIES and the final callback URL.
     * This is the only way to get cookies for a Selenium UI test.
     *
     * @return The final callback URL with the authorization code.
     * @throws Exception if any step of the login process fails.
     */
    public String getLoginCallbackUrl() throws Exception {

        // This method is stateful and uses class members like codeVerifier
        
        OkHttpClient client = buildHttpClient(false);
        OkHttpClient noRedirectClient = buildHttpClient(true);

        this.codeVerifier = generateCodeVerifier();
        this.state = "your-own-random-state-" + System.currentTimeMillis();
        String codeChallenge = generateCodeChallenge(this.codeVerifier);

        this.authorizeCallbackUrl = new HttpUrl.Builder()
                .scheme("https")
                .host("company-sb1.aprimo.com")
                .encodedPath("/login/connect/authorize/callback")
                .addQueryParameter("client_id", CLIENT_ID)
                .addQueryParameter("redirect_uri", REDIRECT_URI)
                .addQueryParameter("response_type", "code")
                .addQueryParameter("scope", SCOPE) // Use same scope
                .addQueryParameter("state", this.state)
                .addQueryParameter("code_challenge", codeChallenge)
                .addQueryParameter("code_challenge_method", "S256")
                .build();

        String returnUrlValue = authorizeCallbackUrl.encodedPath() + "?" + authorizeCallbackUrl.encodedQuery();
        HttpUrl authUrl = HttpUrl.parse(BASE_URL + LOGIN_PATH)
                .newBuilder()
                .addQueryParameter("ReturnUrl", returnUrlValue)
                .addQueryParameter("acr_values", "loginEntry:0")
                .build();

        System.out.println("(UI Flow) Step 1: GET Login Page...");
        Request getLoginRequest = new Request.Builder().url(authUrl).build();
        String loginPageHtml;
        try (Response loginPageResponse = client.newCall(getLoginRequest).execute()) {
            if (!loginPageResponse.isSuccessful()) {
                throw new java.io.IOException("Failed to GET login page: " + loginPageResponse.code());
            }
            loginPageHtml = loginPageResponse.body().string();
        }
        Document loginDoc = Jsoup.parse(loginPageHtml, authUrl.toString());

        System.out.println("(UI Flow) Step 2: POST Login Form...");
        Element loginForm = loginDoc.select("form").first();
        Element loginButton = loginForm.select("button[name=loginButton]").first();
        if (loginButton == null) {
            throw new RuntimeException("Could not find login button with name 'loginButton' in HTML");
        }
        String postUrl = loginButton.absUrl("formaction");

        FormBody.Builder formBuilder = new FormBody.Builder();
        for (Element input : loginForm.select("input[type=hidden]")) {
            formBuilder.add(input.attr("name"), input.attr("value"));
        }
        formBuilder.add("Username", this.username);
        formBuilder.add("Password", this.password);
        formBuilder.add("loginButton", "login");

        Request postLoginRequest = new Request.Builder()
                .url(postUrl)
                .post(formBuilder.build())
                .build();

        try (Response postLoginResponse = noRedirectClient.newCall(postLoginRequest).execute()) {
            if (!postLoginResponse.isRedirect()) {
                System.err.println("Login POST failed. Server returned code: " + postLoginResponse.code());
                throw new RuntimeException("Login POST failed. Expected a 302 redirect, got: " + postLoginResponse.code());
            }
        }
        System.out.println("(UI Flow) Step 3: Login POST successful. Session cookies are set.");

        System.out.println("(UI Flow) Step 4: GET Authorize URL...");
        Request authorizeRequest = new Request.Builder()
                .url(this.authorizeCallbackUrl)
                .get()
                .build();

        String callbackUrlWithCode;
        try (Response finalRedirectResponse = noRedirectClient.newCall(authorizeRequest).execute()) {
            callbackUrlWithCode = finalRedirectResponse.header("Location");
        }

        if (callbackUrlWithCode == null || !callbackUrlWithCode.contains("code=")) {
            throw new RuntimeException("Login flow failed. Final URL did not contain 'code=': " + callbackUrlWithCode);
        }

        String finalUrl = this.authorizeCallbackUrl.resolve(callbackUrlWithCode).toString();
        System.out.println("(UI Flow) Step 5: Programmatic login successful. Callback URL acquired.");
        return finalUrl;
    }

    /**
     * [FOR API TESTS]
     * Performs the stable, single-call "Resource Owner Password" (ROP) flow
     * to directly exchange user credentials for an API Access Token.
     * This is the recommended method for API tests.
     *
     * @return The API Access Token (Bearer Token).
     * @throws Exception if the token exchange fails.
     */
    public String getApiAccessToken() throws Exception {

        System.out.println("(API Flow) Step 1: Building ROP token request...");
        
        // This is the new, simple request body
        FormBody tokenRequestBody = new FormBody.Builder()
                .add("grant_type", "password")
                .add("username", this.username)
                .add("password", this.password)
                .add("client_id", CLIENT_ID)
                .add("scope", SCOPE)
                // Note: No client_secret is provided in this attempt.
                .build();

        Request tokenRequest = new Request.Builder()
                .url(BASE_URL + TOKEN_PATH)
                .post(tokenRequestBody)
                .build();

        // We must use the client with proxy/SSL settings
        OkHttpClient client = buildHttpClient(false);
        String responseBody;

        System.out.println("(API Flow) Step 2: Exchanging credentials for token...");
        try (Response tokenResponse = client.newCall(tokenRequest).execute()) {
            responseBody = tokenResponse.body().string(); // Read body *before* checking success
            if (!tokenResponse.isSuccessful()) {
                throw new java.io.IOException("Token exchange failed (ROP): " + tokenResponse.code()
                        + " " + responseBody);
            }
        }

        String accessToken = parseAccessToken(responseBody);
        if (accessToken == null) {
            throw new RuntimeException("Could not parse 'access_token' from response: " + responseBody);
        }
        
        System.out.println("(API Flow) Step 3: Access Token acquired successfully.");
        return accessToken;
    }

    /**
     * Returns the CookieStore containing the session cookies
     * acquired after a successful UI-flow login.
     *
     * @return The CookieStore.
     */
    public CookieStore getCookieStore() {
        if (this.cookieManager == null) {
            throw new IllegalStateException("Login must be performed before cookies can be retrieved.");
        }
        return this.cookieManager.getCookieStore();
    }


    // --- Private Helper Methods ---

    /**
     * Builds the OkHttpClient, including all proxy and SSL bypass logic.
     *
     * @param disableRedirects True if the client should NOT follow 302 redirects.
     * @return A configured OkHttpClient.
     */
    private OkHttpClient buildHttpClient(boolean disableRedirects) {
        
        // --- !! PROXY CONFIGURATION FOR OFFICE NETWORKS !! ---
        // Find these values in your office browser's network settings or from IT
        
        // 1. SET YOUR PROXY HOST AND PORT (from IntelliJ or IT)
        final String PROXY_HOST = "proxy-xy.company.net"; // e.g., webproxy.yourcompany.com
        final int PROXY_PORT = 2011; // e.g., 8080 or 9000

        // 2. UNCOMMENT THIS LINE to enable the proxy
        // Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(PROXY_HOST, PROXY_PORT));
        
        // 3. UNCOMMENT THIS BLOCK if your proxy requires a username/password
        /*
        Authenticator proxyAuthenticator = new Authenticator() {
            @Override public Request authenticate(Route route, Response response) throws java.io.IOException {
                // 4. EDIT THIS with your office username/password
                String credential = Credentials.basic("your-proxy-username", "your-proxy-password"); 
                return response.request().newBuilder()
                        .header("Proxy-Authorization", credential)
                        .build();
            }
        };
        */

        // 5. Create the "Trust All" SSL manager (for corporate firewalls)
        OkHttpClient.Builder clientBuilder = createUnsafeOkHttpClientBuilder();

        // 6. Apply all configurations
        clientBuilder
                .cookieJar(new JavaNetCookieJar(this.cookieManager));
                
        // 7. UNCOMMENT the proxy settings if needed
        // clientBuilder.proxy(proxy);
        // clientBuilder.proxyAuthenticator(proxyAuthenticator);
                
        if (disableRedirects) {
            clientBuilder.followRedirects(false);
        }

        return clientBuilder.build();
    }

    /**
     * Creates an OkHttpClient.Builder that trusts all SSL certificates.
     * Used to bypass corporate firewall SSL inspection.
     * WARNING: Insecure, do not use for production code.
     */
    private OkHttpClient.Builder createUnsafeOkHttpClientBuilder() {
        try {
            final TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }
                    }
            };

            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = new OkHttpClient.Builder();
            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCpts[0]);
            builder.hostnameVerifier((hostname, session) -> true);
            return builder;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create unsafe SSL context", e);
        }
    }

    private String generateCodeVerifier() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[64];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateCodeChallenge(String verifier) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String extractParamFromUrl(String url, String paramName) {
        try {
            java.net.URL parsedUrl = new java.net.URL(url);
            String query = parsedUrl.getQuery();
            if (query == null) return null;

            for (String pair : query.split("&")) {
                int idx = pair.indexOf("=");
                if (idx > 0 && java.net.URLDecoder.decode(pair.substring(0, idx), "UTF-8").equals(paramName)) {
                    return java.net.URLDecoder.decode(pair.substring(idx + 1), "UTF-8");
                }
            }
            return null;
        } catch (Exception e) {
            System.err.println("Warning: Could not parse URL parameter: " + e.getMessage());
            return null;
        }
    }

    private String parseAccessToken(String jsonResponse) {
        // Use regex for a simple, no-dependency JSON parse
        Pattern p = Pattern.compile("\"access_token\":\\s*\"(.*?)\"");
        Matcher m = p.matcher(jsonResponse);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }

    /**
     * Main method to test the *new* API ROP flow.
     */
    public static void main(String[] args) {
        // --- !! UPDATE THESE !! ---
        final String TEST_USERNAME = "arif_ao";
        final String TEST_PASSWORD = "testing@12345";
        // --- !! UPDATE THESE !! ---

        if (TEST_USERNAME.equals("your-test-username")) {
            System.err.println("Please update TEST_USERNAME and TEST_PASSWORD in the main() method.");
            return;
        }
        
        // --- !! PROXY TEST !! ---
        // Uncomment this block to test with your proxy settings
        /*
        final String PROXY_HOST = "proxy-xy.company.net";
        final int PROXY_PORT = 2011;
        final String PROXY_USER = "your-proxy-username";
        final String PROXY_PASS = "your-proxy-password";
        
        AprimoLogin.ProxyConfig proxyConfig = new AprimoLogin.ProxyConfig(
                PROXY_HOST, PROXY_PORT, PROXY_USER, PROXY_PASS
        );
        AprimoLogin loginSession = new AprimoLogin(TEST_USERNAME, TEST_PASSWORD, proxyConfig);
        */
        
        // Standard (no proxy) test
        AprimoLogin loginSession = new AprimoLogin(TEST_USERNAME, TEST_PASSWORD, null);

        try {
            System.out.println("--- Testing new getApiAccessToken() (ROP) flow ---");
            String accessToken = loginSession.getApiAccessToken();
            System.out.println("\n--- API ACCESS TOKEN ---");
            System.out.println(accessToken);
            System.out.println("\n--- ROP FLOW SUCCESS ---");

        } catch (Exception e) {
            System.err.println("\n--- ROP LOGIN FAILED ---");
            e.printStackTrace();
        }
    }
}
