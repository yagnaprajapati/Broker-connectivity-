package com.quantTech.broker_connectivity.broker;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.quantTech.broker_connectivity.broker.data.CandleData;
import com.warrenstrange.googleauth.GoogleAuthenticator;

@Component
public class ZerodhaKiteApi {

	private HttpClient client1;
	private static Map<String, String> headers = new HashMap<>();
	private String userApikey;
	private String userId;
	private String password;
	private String secretKey;
	private String authKey;

	private static final ObjectMapper objectMapper = new ObjectMapper();

	public ZerodhaKiteApi() {
		System.out.println("ZerodhaKiteApi constructor called");
		System.out.println("----------------------------------------------------------------------------------------------------------------");
		this.client1 = HttpClient.newBuilder().followRedirects(Redirect.NEVER).version(HttpClient.Version.HTTP_1_1)
				.connectTimeout(Duration.ofSeconds(10)).build();
		
//		this.headers.put("User-Agent",
//				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3");
//		this.headers.put("Accept", "application/json");
//		this.headers.put("Content-Type", "application/x-www-form-urlencoded");
	}

	// Login URL for Kite Connect	
	private String getZerodhaLoginBaseURL(String apiKey) {
		return "https://kite.trade/connect/login?api_key=" + apiKey + "&v=3";
	}

	// Login URL for Kite Zerodha UI
	private String getZerodhaLoginToZerodhaBaseURL(String apiKey) {
		return "https://kite.zerodha.com/connect/login?api_key=" + apiKey + "&v=3";
	}

	// Build base HTTP GET request
	private HttpRequest getBaseRequest(String url, Map<String, String> customHeaders) {
		Map<String, String> allHeaders = customHeaders != null ? customHeaders : headers;

		HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().uri(URI.create(url)).GET();

		for (Map.Entry<String, String> entry : allHeaders.entrySet()) {
			requestBuilder.header(entry.getKey(), entry.getValue());
		}

		return requestBuilder.build();
	}

	// Extra headers as getter
	private Map<String, String> getExtraHeaders() {
		Map<String, String> extra = new HashMap<>();
		extra.put("Access-Control-Allow-Origin", "*");
		extra.put("Content-Type", "application/x-www-form-urlencoded");
		return extra;
	}
	
	public static HashMap<String, Integer> loadInstrumentTokenMap() {
        HashMap<String, Integer> instrumentMap = new HashMap<>();
        String url = "https://api.kite.trade/instruments";

        try {
            URL instrumentsUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) instrumentsUrl.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                System.err.println("Failed to fetch instrument list. HTTP code: " + responseCode);
                return instrumentMap;
            }

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream())
            );

            String line;
            boolean headerSkipped = false;
            while ((line = reader.readLine()) != null) {
                // Skip CSV header
                if (!headerSkipped) {
                    headerSkipped = true;
                    continue;
                }

                // CSV format:
                // instrument_token,exchange_token,tradingsymbol,name,last_price,expiry,strike,token,lot_size,instrument_type,segment,exchange
                String[] cols = line.split(",", -1);
                if (cols.length < 12) continue;

                String instrumentType = cols[9];
                String exchange = cols[11];
                String tradingsymbol = cols[2];
                String segment = cols[10];

                // Only include equity stocks for NSE
                if ("NSE".equals(exchange) && "EQ".equals(instrumentType)) {
                    int instrumentToken = Integer.parseInt(cols[0]);
                    String key = exchange + ":" + tradingsymbol;
                    instrumentMap.put(key, instrumentToken);
                }
            }

            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return instrumentMap;
    }

	private boolean checkResponseStatus(String responseBody, int statusCode, String userId) {
		try {
			if (statusCode != 200) {
				debugLogs("_checkResponseStatus(): userId: " + userId + ", statusCode: " + statusCode);
				return false;
			}

			JsonNode jsonNode = objectMapper.readTree(responseBody);
			return jsonNode.has("status") && "success".equalsIgnoreCase(jsonNode.get("status").asText());

		} catch (Exception e) {
			System.err.println("[ERROR] userId: " + userId + " - " + e.getMessage());
			return false;
		}
	}

	private void updateCookie(HttpResponse<?> response) {
		Optional<List<String>> cookieHeader = Optional.ofNullable(response.headers().map().get("set-cookie"));
		cookieHeader.ifPresent(this::updateCookie);
		System.out.println("[DEBUG] Updated cookies: " + headers.get("cookie"));
		System.out.println("cookieHeader: " + cookieHeader.orElse(new ArrayList<>()));
	}

	private void updateCookie(List<String> setCookieHeaders) {
		System.out.println("YAGNA");
		List<String> cookieList = headers.containsKey("cookie") ? Arrays.stream(headers.get("cookie").split(";"))
				.map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList()) : new ArrayList<>();

		for (String rawHeader : setCookieHeaders) {
			List<String> splitCookies = Arrays.stream(rawHeader.split(",")).map(String::trim).filter(s -> !s.isEmpty())
					.collect(Collectors.toList());

			for (String cookieString : splitCookies) {
				String[] partsArray = Arrays.stream(cookieString.split(";")).map(String::trim).filter(s -> !s.isEmpty())
						.toArray(String[]::new);

				if (partsArray.length == 0)
					continue;

				String cookie = partsArray[0].trim();
				if (!cookie.contains("="))
					continue;

				String key = cookie.substring(0, cookie.indexOf("="));
				String value = cookie.substring(key.length() + 1);

				switch (key) {
				case "_cfuvid":
				case "kf_session":
				case "user_id":
				case "public_token":
				case "enctoken":
				case "session":
					addOrReplaceCookie(cookieList, key, value);
					break;
				}
			}
		}

		headers.put("cookie", String.join("; ", cookieList));
	}

	private void addOrReplaceCookie(List<String> list, String key, String value) {
		int index = -1;
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).toLowerCase().startsWith(key.toLowerCase() + "=")) {
				index = i;
				break;
			}
		}
		if (index != -1) {
			list.set(index, key + "=" + value);
		} else {
			list.add(key + "=" + value);
		}
	}

	private void debugLogs(String message) {
		System.out.println("[DEBUG] " + message);
		// Replace with logger.debug() if you're using Log4j/SLF4J
	}

	private static final String LOCATION_KEY = "Location";
	private static final String SESSION_ID_KEY = "sess_id";

	// 1. Check if response has Location header
	private boolean checkLocationHeaders(HttpResponse<?> response) {
		System.out.println("Checking Location headers in response: " + response.headers().map());
		
		boolean value = response.headers().firstValue("location").isPresent()
				|| response.headers().map().containsKey(LOCATION_KEY);
		System.out.println("Location header present: " + value);
		return value;
	}

	// 2. Generate TOTP from secret key
	private String generateTOTP(String secretBase32) {
		System.out.println("Generating TOTP for secret: " + secretBase32);
		if (secretBase32 == null || secretBase32.isEmpty())
			return null;

		try {
			System.out.println("Decoding base32 secret: " + secretBase32);
			GoogleAuthenticator gAuth = new GoogleAuthenticator();
			System.out.println("Decoded secret: " + Arrays.toString(decodeBase32(secretBase32)));
			int code = gAuth.getTotpPassword(secretBase32);
			System.out.println("Generated TOTP code: " + code);
			return String.format("%06d", code); // Always return 6-digit string
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	// Helper method to decode base32 secret (e.g., from Google Authenticator)
	private byte[] decodeBase32(String base32) {
		// Replace with a reliable Base32 decoder if needed.
		return new org.apache.commons.codec.binary.Base32().decode(base32);
	}

	// 3. Build first redirect URL with apiKey and sessionId
	private String getZerodhaFirstRedirectUrl(String apiKey, String sessionId) {
		return "https://kite.zerodha.com/connect/login?api_key=" + apiKey + "&sess_id=" + sessionId;
	}

	// 4. Check market data access using REST API
	public String checkMarketDataAccess(String accessToken) throws Exception {
		String apiKey = userApikey;

		HttpClient client = HttpClient.newHttpClient();

		HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://api.kite.trade/quote/ltp?i=NSE:INFY"))
				.GET().header("Authorization", "token " + apiKey + ":" + accessToken).build();

		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		String content = response.body();

		if (response.statusCode() != 200) {
			if (content.contains("permission") || content.contains("access") || content.contains("403")) {
				return "Market Data (WebSocket) access NOT available.";
			} else {
				return "Some other error: " + content;
			}
		}

		return "Market Data (WebSocket) access LIKELY available (REST quote worked).";
	}

	

	public static Map<String, String> splitQuery(URI uri) throws UnsupportedEncodingException {
		Map<String, String> queryPairs = new HashMap<>();
		String query = uri.getQuery();
		if (query == null || query.isEmpty())
			return queryPairs;

		String[] pairs = query.split("&");
		for (String pair : pairs) {
			int idx = pair.indexOf("=");
			if (idx > 0 && idx < pair.length() - 1) {
				String key = URLDecoder.decode(pair.substring(0, idx), "UTF-8");
				String value = URLDecoder.decode(pair.substring(idx + 1), "UTF-8");
				queryPairs.put(key, value);
			} else if (idx == pair.length() - 1) {
				String key = URLDecoder.decode(pair.substring(0, idx), "UTF-8");
				queryPairs.put(key, "");
			}
		}
		return queryPairs;
	}

	public static HttpRequest buildPostRequest(String url, Map<String, String> formData, Map<String, String> headers) {
		StringJoiner sj = new StringJoiner("&");
		for (Map.Entry<String, String> entry : formData.entrySet()) {
			sj.add(encode(entry.getKey()) + "=" + encode(entry.getValue()));
		}

		HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().uri(URI.create(url))
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(BodyPublishers.ofString(sj.toString()));

		for (Map.Entry<String, String> header : headers.entrySet()) {
			requestBuilder.header(header.getKey(), header.getValue());
		}

		return requestBuilder.build();
	}

	private static String encode(String value) {
		try {
			return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8.toString());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public static String getRedirectLocation(String urlStr) throws IOException {
	    HttpURLConnection connection = (HttpURLConnection) new URL(urlStr).openConnection();
	    connection.setInstanceFollowRedirects(false); // Disable automatic redirection
	    connection.setRequestMethod("GET");
	    // ✅ Set cookie header if required
	    try {
			try {
				connection.setRequestProperty("Cookie", headers.get("cookie"));
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} // <- Use your actual cookie map
	    connection.connect();

	    int responseCode = connection.getResponseCode();
	    System.out.println("Response Code: " + responseCode);
	    System.out.println("Location header: " + connection.getHeaderField("Location"));
	    if (responseCode == HttpURLConnection.HTTP_MOVED_TEMP ||
	        responseCode == HttpURLConnection.HTTP_MOVED_PERM ||
	        responseCode == HttpURLConnection.HTTP_SEE_OTHER) {
	    	System.out.println("Redirect detected");
	    	System.out.println("Location header: " + connection.getHeaderField("Location"));
	        String redirectUrl = connection.getHeaderField("Location");
	        return redirectUrl;
	    }
	    

	    return null; // No redirect
	}
	
	public static String postAndGetRedirect(String urlStr, Map<String, String> formData) throws IOException {
	    return postAndGetRedirect(urlStr, formData, Map.of()); // call the 3-arg version with empty headers
	}
	
	public static String postAndGetRedirect(String urlStr, Map<String, String> formData, Map<String, String> headers) throws IOException {
	    URL url = new URL(urlStr);
	    HttpURLConnection connection = (HttpURLConnection) url.openConnection();

	    connection.setInstanceFollowRedirects(false); // We want to read the redirect URL, not follow it
	    connection.setRequestMethod("POST");
	    connection.setDoOutput(true); // Enable sending body
	    connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

	    // Add custom headers (like Cookie)
	    for (Map.Entry<String, String> entry : headers.entrySet()) {
	        connection.setRequestProperty(entry.getKey(), entry.getValue());
	    }

	    // Prepare form body
	    StringBuilder requestBody = new StringBuilder();
	    for (Map.Entry<String, String> entry : formData.entrySet()) {
	        if (requestBody.length() != 0) requestBody.append("&");
	        requestBody.append(java.net.URLEncoder.encode(entry.getKey(), "UTF-8"));
	        requestBody.append("=");
	        requestBody.append(java.net.URLEncoder.encode(entry.getValue(), "UTF-8"));
	    }

	    // Send form body
	    try (OutputStream os = connection.getOutputStream()) {
	        os.write(requestBody.toString().getBytes("UTF-8"));
	    }

	    // Get Location header from response
	    int responseCode = connection.getResponseCode();
	    if (responseCode == HttpURLConnection.HTTP_MOVED_TEMP ||
	        responseCode == HttpURLConnection.HTTP_MOVED_PERM ||
	        responseCode == HttpURLConnection.HTTP_SEE_OTHER) {
	        return connection.getHeaderField("Location");
	    }

	    return null; // Not a redirect
	}

	// -----------------------------------------------------------------------
	// Method to generate request token based on user authorization status
	// 1. If already authorized -> retrieve token
	// 2. If not authorized -> perform login and authorization flow
	// 3. If user is invalid -> return null
	// @return Request token
	// author: yprajapati
	// date: 25 Jun 2025
	// -----------------------------------------------------------------------
	public String getRequestToken() {
		try {
			System.out.println("getRequestToken: " + userId + ", " + userApikey + ", " + authKey);
			headers.clear();

			// Step 1: Hit initial Zerodha login URL
			String baseLoginUrl = getZerodhaLoginBaseURL(userApikey);
			System.out.println("baseLoginUrl: " + baseLoginUrl);
			HttpRequest baseLoginRequest = getBaseRequest(baseLoginUrl, headers);
			System.out.println("baseLoginRequest: " + baseLoginRequest);
			HttpResponse<String> baseLoginResponse = client1.send(baseLoginRequest,
					HttpResponse.BodyHandlers.ofString());
			System.out.println("Here 1");
			updateCookie(baseLoginResponse);
			boolean isTrue = checkLocationHeaders(baseLoginResponse);
			System.out.println("baseLoginResponse: " + baseLoginResponse.headers().map());
			System.out.println("is True: " + isTrue);
			if (!isTrue) {
				System.out.println("No location header found in base login response.");
				return null;
			}
			else
				System.out.println("Location header found in base login response.");
			
			System.out.println("baseLoginResponse: " + baseLoginResponse.body());

			// Step 2: Hit connect login URL
			String loginUrl = getZerodhaLoginToZerodhaBaseURL(userApikey);
			System.out.println("loginUrl: " + loginUrl);
			HttpRequest loginRequest = getBaseRequest(loginUrl, headers);
			System.out.println("loginRequest: " + loginRequest);
			HttpResponse<String> loginResponse = client1.send(loginRequest, HttpResponse.BodyHandlers.ofString());
			System.out.println("loginResponse: " + loginResponse.body());
			updateCookie(loginResponse);
			System.out.println("Here2");
			if (!checkLocationHeaders(loginResponse))
				return null;

			// Step 3: Parse session_id from redirect URL
			String redirectUrl = getLocationFromHeaders(loginResponse);
			System.out.println("redirectUrl: " + redirectUrl);
			URI uri = URI.create(redirectUrl);
			System.out.println("uri: " + uri);
			Map<String, String> queryParams = splitQuery(uri);
			System.out.println("queryParams: " + queryParams);
			String sessionId = queryParams.get("sess_id");
			if (sessionId == null)
				return null;

			// Step 4: Post user_id and password
			System.out.println("userId: " + userId + ", password: " + password);
			Map<String, String> formData = Map.of("user_id", userId, "password", password);
			HttpRequest loginPostRequest = buildPostRequest("https://kite.zerodha.com/api/login", formData, headers);
			HttpResponse<String> loginPostResponse = client1.send(loginPostRequest,
					HttpResponse.BodyHandlers.ofString());
			updateCookie(loginPostResponse);

			System.out.println("loginPostResponse: " + loginPostResponse.body());
			System.out.println("loginPostResponse status code: " + loginPostResponse.statusCode());
			if (loginPostResponse.statusCode() != 200)
				return null;

			// Step 5: Parse response and generate TOTP
			JsonNode json = objectMapper.readTree(loginPostResponse.body());
			System.out.println("json: " + json);
			JsonNode data = json.get("data");
			System.out.println("data: " + data);
			String requestId = data.get("request_id").asText();
			System.out.println("requestId: " + requestId);
			String twofaType = data.get("twofa_type").asText();
			System.out.println("twofaType: " + twofaType);
			String finalOTP = null;
			if ("totp".equals(twofaType)) {
				System.out.println("Generating TOTP for user: " + userId);
				finalOTP = generateTOTP(authKey);
				System.out.println("Generated TOTP: " + finalOTP);
			}
			if (finalOTP == null)
				return null;

			// Step 6: Submit TOTP
			System.out.println("Submitting TOTP for user: " + userId);
			Map<String, String> totpForm = Map.of("user_id", userId, "request_id", requestId, "twofa_value", finalOTP,
					"twofa_type", "totp", "skip_session", "true");
			HttpRequest totpRequest = buildPostRequest("https://kite.zerodha.com/api/twofa", totpForm, headers);
			System.out.println("totpRequest: " + totpRequest);
			HttpResponse<String> totpResponse = client1.send(totpRequest, HttpResponse.BodyHandlers.ofString());
			System.out.println("totpResponse: " + totpResponse.body());
			if (!checkResponseStatus(totpResponse.body(), totpResponse.statusCode(), userId))
			{
				System.out.println("Failed to submit TOTP or invalid response.");
				return null;
			}
			else
				System.out.println("Successfully submitted TOTP for user: " + userId);
			updateCookie(totpResponse);

			// Step 7: Follow redirect chain
			System.out.println("Following redirect chain to get request token...");
			String firstRedirect = getZerodhaFirstRedirectUrl(userApikey, sessionId);
			System.out.println("firstRedirect: " + firstRedirect);
			
			String secondRedirect = getRedirectLocation(firstRedirect);
			System.out.println("secondRedirect: " + secondRedirect);
			String thirdRedirect = getRedirectLocation(secondRedirect);
			System.out.println("thirdRedirect: " + thirdRedirect);

			if (thirdRedirect.contains("/connect/authorize")) {
				String finishUrl = "https://kite.zerodha.com/connect/finish";
				Map<String, String> body = Map.of("sess_id", sessionId, "api_key", userApikey, "authorize", "true");
				thirdRedirect = postAndGetRedirect(finishUrl, body);
			}

			URI finalUri = URI.create(thirdRedirect);
			Map<String, String> finalQuery = splitQuery(finalUri);
			return finalQuery.get("request_token");

		} catch (Exception e) {
			//logger.severe("getRequestToken: " + e.getMessage());
			return null;
		}
	}

	// Utility methods like GetBaseRequest, buildPostRequest, updateCookie,
	// getLocationFromHeaders,
	// splitQuery, generateTOTP, checkLocationHeader, checkResponseStatus,
	// getRedirectLocation, and
	// postAndGetRedirect must be implemented as helpers for full functionality.

	private String getLocationFromHeaders(HttpResponse<String> loginResponse) {
		// TODO Auto-generated method stub
		return loginResponse.headers().firstValue("location")
				.orElseThrow(() -> new RuntimeException("Location header not found in response"));
	}
	
	

	// -----------------------------------------------------------------------
		// Method to generate Access Token
		// @return Access Token
		// author: yprajapati
		// date: 25 Jun 2025
		// -----------------------------------------------------------------------
		public String getAccessToken(HashMap<String, String> credential) {
			
			String accessToken = null;
			System.out.println("getAccessToken: " + credential);
			try {			
				this.userId = credential.get("username");
				this.password = credential.get("password");
				this.userApikey = credential.get("apiKey");
				this.secretKey = credential.get("apiSec");
				this.authKey = credential.get("authKey");
				// Get request token from Zerodha API
				String requestToken = getRequestToken(); // Replace with actual implementation

				if (requestToken != null) {
					// Construct checksum using SHA256: apiKey + requestToken + secretKey
					String checksumInput = userApikey + requestToken + secretKey;

					MessageDigest digest = MessageDigest.getInstance("SHA-256");
					byte[] hash = digest.digest(checksumInput.getBytes(StandardCharsets.UTF_8));

					StringBuilder checksumBuilder = new StringBuilder();
					for (byte b : hash) {
						checksumBuilder.append(String.format("%02x", b));
					}
					String checksum = checksumBuilder.toString();

					// Prepare URL-encoded form data for POST request
					StringJoiner sj = new StringJoiner("&");
					sj.add("api_key=" + encode(userApikey));
					sj.add("request_token=" + encode(requestToken));
					sj.add("checksum=" + encode(checksum));
					String form = sj.toString();

					// Send POST request to token endpoint
					HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://api.kite.trade/session/token"))
							.header("Content-Type", "application/x-www-form-urlencoded")
							.POST(HttpRequest.BodyPublishers.ofString(form)).build();

					HttpResponse<String> response = client1.send(request, HttpResponse.BodyHandlers.ofString());

					// Parse JSON response and extract access_token
					ObjectMapper mapper = new ObjectMapper();
					JsonNode root = mapper.readTree(response.body());

					if (root.has("data") && root.get("data").has("access_token")) {
						accessToken = root.get("data").get("access_token").asText();
					}
				}
			} catch (Exception ex) {
				// ((Object) logger).severe("getAccessToken: " + ex.getMessage());
			}

			return accessToken;
		}

		public CandleData getOHLCData(String ticker, String apiKey, String accessToken) {
			// TODO Auto-generated method stub
			try {
				
				String instrument = "NSE:" + ticker; // Assuming NSE exchange, adjust as needed
	            String urlStr = "https://api.kite.trade/quote?i=NSE:" + ticker;
	            URL url = new URL(urlStr);
	            //URL url = new URL(urlStr);
	            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
	            conn.setRequestMethod("GET");

	            // 🔥 Critical headers
	            conn.setRequestProperty("X-Kite-Version", "3");
	            conn.setRequestProperty("Authorization", "token " + apiKey + ":" + accessToken);  // Must have space after 'token'

	            // Optional: Set User-Agent to mimic browser
	            conn.setRequestProperty("User-Agent", "Mozilla/5.0");

	            int responseCode = conn.getResponseCode();
	            System.out.println("HTTP Response Code: " + responseCode);

	            if (responseCode == 200) {
	                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
	                StringBuilder response = new StringBuilder();
	                String inputLine;

	                while ((inputLine = in.readLine()) != null) {
	                    response.append(inputLine);
	                }
	                in.close();

	                JSONObject json = new JSONObject(response.toString());
	                JSONObject data = json.getJSONObject("data").getJSONObject(instrument);
	                JSONObject ohlc = data.getJSONObject("ohlc");

	                double open = ohlc.getDouble("open");
	                double high = ohlc.getDouble("high");
	                double low = ohlc.getDouble("low");
	                double close = ohlc.getDouble("close");

	                return new CandleData(ticker, open, high, low, close, 0);
	            } else {
	                throw new RuntimeException("403 Forbidden or error response from Kite API");
	            }
	            
	            
	            
	            
	            
	            
	            
	            
	            
	            
	            
	            
//	            System.out.println("Fetching OHLC data from URL: " + url);
//	            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
//	            System.out.println("Setting up connection with API Key: " + apiKey + " and Access Token: " + accessToken);
//	            conn.setRequestMethod("GET");
//	            conn.setRequestProperty("X-Kite-Version", "3");
//	            conn.setRequestProperty("Authorization", "token=" + apiKey + ":" + accessToken);
//
//	            int responseCode = conn.getResponseCode();
//	            System.out.println("Response Code: " + responseCode);
//	            if (responseCode == 200) {
//	                BufferedReader in = new BufferedReader(
//	                        new InputStreamReader(conn.getInputStream())
//	                );
//	                StringBuilder response = new StringBuilder();
//	                String inputLine;
//
//	                while ((inputLine = in.readLine()) != null) {
//	                    response.append(inputLine);
//	                }
//	                in.close();
//
//	                JSONObject json = new JSONObject(response.toString());
//	                JSONObject data = json.getJSONObject("data").getJSONObject("NSE:RELIANCE");
//	                JSONObject ohlc = data.getJSONObject("ohlc");
//
//	                double open = ohlc.getDouble("open");
//	                double high = ohlc.getDouble("high");
//	                double low = ohlc.getDouble("low");
//	                double close = ohlc.getDouble("close");
//
//	                return new OHLCData(ticker, open, high, low, close, 0); // Volume is set to 0 as it's not provided in the response
//	            } else {
//	                System.out.println("HTTP Error Code: " + responseCode);
//	            }

	        } catch (Exception e) {
	            e.printStackTrace();
	        }

	        return null; // return null in case of failure
		}

		public List<CandleData> getHistoricalData(String apiKey, String accessToken, int instrumentToken,
				String interval, String fromDate, String toDate) {
			// TODO Auto-generated method stub
			
			List<CandleData> candleList = new ArrayList<>();

	        try {
	            String urlStr = String.format(
	                "https://api.kite.trade/instruments/historical/%d/%s?from=%s&to=%s",
	                instrumentToken, interval, fromDate, toDate
	            );

	            System.out.println("Fetching from: " + urlStr);
	            URL url = new URL(urlStr);
	            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
	            conn.setRequestMethod("GET");

	            conn.setRequestProperty("X-Kite-Version", "3");
	            conn.setRequestProperty("Authorization", "token " + apiKey + ":" + accessToken);
	            conn.setRequestProperty("User-Agent", "Mozilla/5.0");

	            int responseCode = conn.getResponseCode();
	            System.out.println("HTTP Response Code: " + responseCode);

	            if (responseCode == 200) {
	                BufferedReader in = new BufferedReader(
	                    new InputStreamReader(conn.getInputStream())
	                );
	                StringBuilder response = new StringBuilder();
	                String inputLine;

	                while ((inputLine = in.readLine()) != null) {
	                    response.append(inputLine);
	                }
	                in.close();

	                JSONObject json = new JSONObject(response.toString());
	                JSONArray candles = json.getJSONObject("data").getJSONArray("candles");

	                for (int i = 0; i < candles.length(); i++) {
	                    JSONArray candle = candles.getJSONArray(i);
	                    String time = candle.getString(0);
	                    double open = candle.getDouble(1);
	                    double high = candle.getDouble(2);
	                    double low = candle.getDouble(3);
	                    double close = candle.getDouble(4);
	                    double volume = candle.getDouble(5);

	                    candleList.add(new CandleData(time, open, high, low, close, volume));
	                }
	            } else {
	                System.out.println("Failed to fetch historical data. HTTP code: " + responseCode);
	            }

	        } catch (Exception e) {
	            e.printStackTrace();
	        }

	        return candleList;
		}

}
