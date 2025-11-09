Here is a step-by-step explanation of exactly what the `getLoginCallbackUrl` function does in your `AprimoLogin.java` file.

### High-Level Goal: "The Cookie Steal"

The entire purpose of this function is to **get the session cookies** for a specific user and the **final callback URL** (which contains the temporary `code`). It's designed to be the "engine" for your UI tests (`LoginManager.createLoggedInBrowser`).

It does *not* get the final `access_token`. It only does the first part of the login.

-----

### Step-by-Step Code Explanation

Here is a breakdown of the code, step by step.

#### Step 1: Build the "Robot" (The HTTP Client)

```java
OkHttpClient client = buildHttpClient(false);
OkHttpClient noRedirectClient = buildHttpClient(true);
```

This is the most important setup. It calls your `buildHttpClient` helper method, which creates a "robot browser" (`OkHttpClient`) with all your office's special network settings:

1.  **Proxy:** It's configured to go through your office proxy server (e.g., `proxy-xy.company.net:2011`).
2.  **SSL Bypass:** It's set to "trust all certificates" to bypass the `SSLException` from your firewall.
3.  **Cookie Jar:** It has a `CookieManager` attached, which acts like a "cookie jar" to automatically save any cookies the server gives it.

#### Step 2: Prepare the "Lock and Key" (OIDC Security)

```java
String codeVerifier = generateCodeVerifier();
String state = "your-own-random-state-" + ...;
String codeChallenge = generateCodeChallenge(this.codeVerifier);
```

This creates the modern security codes required by OIDC:

  * `state`: A unique, random string to prevent "Cross-Site Request Forgery" attacks.
  * `codeVerifier` / `codeChallenge`: A secret and its hash, proving that we are the same client that starts the login and finishes it (called **PKCE**).

#### Step 3: Build the "Two-Part" URL

```java
HttpUrl authorizeCallbackUrl = new HttpUrl.Builder() ... .build();
String returnUrlValue = authorizeCallbackUrl.encodedPath() + ...;
HttpUrl authUrl = HttpUrl.parse(BASE_URL + LOGIN_PATH) ... .build();
```

This was the key trick we discovered.

1.  **Inner URL:** It builds the OIDC authorize URL (`authorizeCallbackUrl`) with all the security parameters from Step 2.
2.  **Outer URL:** It builds the *actual login page* URL (`authUrl`). It then "stuffs" the entire Inner URL into the `ReturnUrl` parameter. This tells the server, "After this person logs in, send them to *this* complex OIDC URL."

#### Step 4: "Scrape" the Login Page (GET)

```java
Request getLoginRequest = new Request.Builder().url(authUrl).build();
Response loginPageResponse = client.newCall(getLoginRequest).execute();
Document loginDoc = Jsoup.parse(loginPageHtml, authUrl.toString());
```

This is the **first network call**. The robot makes a `GET` request to the login page.

  * **Why?** Not to see the page, but to **read its HTML**.
  * The login form has hidden, anti-forgery tokens (like `__RequestVerificationToken`) that are unique for every visit. We *must* copy these tokens, or the server will reject our login as a "bot."
  * `Jsoup` is the tool we use to parse the HTML and find these tokens.

#### Step 5: Perform the Login (POST)

```java
Element loginForm = loginDoc.select("form").first();
Element loginButton = loginForm.select("button[name=loginButton]").first();
// ...
formBuilder.add("Username", this.username);
formBuilder.add("Password", this.password);
// ...
Response postLoginResponse = noRedirectClient.newCall(postLoginRequest).execute();
```

This is the **second network call** and the *actual login*. The robot builds and `POST`s the login form, including:

1.  The `Username` and `Password` (from the constructor).
2.  All the hidden tokens we just "scraped" in Step 4.
3.  The `loginButton` value (which we discovered was also required).

#### Step 6: Check for Success

```java
if (!postLoginResponse.isRedirect()) {
    throw new RuntimeException("Login POST failed...");
}
```

This is the most critical check.

  * **If it's a `302 Redirect` (Success):** The username and password were correct\! The server has now given our robot a **session cookie** (e.g., `.Aprimo`) and put it in our "cookie jar." We are now "logged in" at the API level.
  * **If it's a `200 OK` (Failure):** The login failed. The server just re-sent the login page, probably with an "Invalid Password" error. The code throws an exception.

#### Step 7: Exchange Session for a "Code"

```java
Request authorizeRequest = new Request.Builder()
        .url(this.authorizeCallbackUrl)
        .get()
        .build();
Response finalRedirectResponse = noRedirectClient.newCall(authorizeRequest).execute();
```

This is the **third network call**. Now that our robot is "logged in" (it's holding the session cookie), it makes a `GET` request to the `authorizeCallbackUrl` (the "Inner URL" from Step 3).

The server sees this request and thinks:

1.  "Does this request have a valid session cookie? **Yes.**"
2.  "Is it asking for OIDC authorization? **Yes.**"
3.  "OK, this logged-in user is authorized. I will grant them a temporary `code`."

#### Step 8: Capture and Return the Final URL

```java
String callbackUrlWithCode = finalRedirectResponse.header("Location");
// ...
String finalUrl = this.authorizeCallbackUrl.resolve(callbackUrlWithCode).toString();
return finalUrl;
```

The server "grants the code" by issuing one last `302 Redirect`. The `Location` header of this redirect *is* the final URL you want:
`https://.../signin-callback.html?code=7CCA61F...&state=...`

This function captures that URL from the header and returns it as a string. Your `LoginManager` then uses this URL (and the cookies) to set up the Selenium browser.          
