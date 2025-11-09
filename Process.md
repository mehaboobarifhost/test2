Aprimo Test Automation: Hybrid Login System Documentation

1. Overview: The Problem We Solved

In our test automation, we face two challenges:

UI Login is Slow: Using Selenium to type a username, password, and click "Log In" for every single test is extremely slow and adds minutes to our test runs.

API Tokens are "System" Users: We can't just use a standard API Client ID/Secret. We need to test the UI as specific, real users (like arif_ao or test_user_b) who have different permissions.

2. Our Solution: The "Hybrid Login"

We have implemented a "Hybrid Login" system that gives us the best of both worlds. It is incredibly fast (like an API test) but logs us in as a real user (like a UI test).

Here is the high-level concept:

Step 1: API Login (Headless): A background Java client (OkHttp) performs a programmatic login. It scrapes the login form, submits the user's credentials, and handles all the redirects, just like a real browser.

Step 2: Steal the Cookies: After this successful API login, we "steal" the session cookies the server gives us. These cookies are the server's way of "remembering" that we are logged in.

Step 3: Inject into Browser: We launch a clean, new Selenium browser.

Step 4: Inject Cookies: We inject the stolen cookies into the browser.

Step 5: Go to App: We tell Selenium to go directly to the application's homepage. The server sees the cookies and, as far as it's concerned, we are already logged in.

This entire process skips the UI login page and takes about 1-2 seconds instead of 10-15 seconds.

3. System Architecture: The Two Key Files

Our login system is split into two classes. This separation is the most important part of the design.

AprimoLogin.java - The "Engine Room"

This class is the low-level, complex, and "dirty" part of the system. Think of it as the complex engine inside a car.

Purpose: To handle all the complex, raw HTTP communication.

Key Responsibilities:

Uses OkHttp to make all API calls.

Uses Jsoup to parse the HTML of the login form and find hidden fields.

Handles all complex network issues for the corporate office (Proxy Servers, SSL Certificate Bypassing).

Manages the OIDC "PKCE" security codes (code_verifier, code_challenge).

Exchanges the final code for a real access_token for API tests.

Key Characteristic: BRITTLE

This class is brittle by design. It relies on scraping the HTML of the login page.

When It Breaks: If the Aprimo developers change their login page (e.g., rename a button, add a field), this file will break.

Maintenance: This is the only file you should ever need to edit when the login process breaks.

LoginManager.java - The "Control Panel"

This class is the clean, simple, and stable interface for our framework. Think of it as the "steering wheel" and "gas pedal" for the car.

Purpose: To provide simple, clean functions for your tests to call.

Key Responsibilities:

Hides all complexity. Your test framework never knows about OkHttp, Jsoup, or SSL problems. It just calls a method.

Provides initializeApiToken() to get the API token once for all API tests.

Provides createLoggedInBrowser() to perform the full hybrid login and return a ready-to-use Selenium WebDriver.

Key Characteristic: STABLE

This file should never change. It is the stable "public API" for your test framework.

Your Cucumber hooks and step definitions should only ever call methods from this class.

This design ensures that when the login process breaks, you only have to fix the "engine" (AprimoLogin.java), not the entire "car" (your whole test framework).

4. How to Use in Your Framework

Your test framework (e.g., CucumberHooks.java) only talks to the LoginManager.

For UI Tests (in CucumberHooks.java)

// This hook runs before any @UI-Login test
@Before("@UI-Login")
public void setupUiTest(Scenario scenario) throws Exception {
    
    // We call one simple function from LoginManager
    // It handles everything and gives us a ready-to-use browser
    this.driver = LoginManager.createLoggedInBrowser(TEST_USERNAME, TEST_PASSWORD);
}

// Your step definition can then get the driver
public WebDriver getDriver() {
    return this.driver;
}


For API Tests (in CucumberHooks.java)

// This hook runs ONCE before ALL tests
@BeforeAll
public static void setupSuite() throws Exception {
    
    // We call this one function to get the token for all API tests
    LoginManager.initializeApiToken(TEST_USERNAME, TEST_PASSWORD);
}

// Your API steps can then get the token
public static String getApiAccessToken() {
    return LoginManager.getApiToken();
}
