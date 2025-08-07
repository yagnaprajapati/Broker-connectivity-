package com.quantTech.broker_connectivity.credential;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

public class Credentials {

	@JsonProperty("apiKey")
	@NotBlank(message = "API Key cannot be empty")
    private String userApikey;

	@JsonProperty("username")
    @NotEmpty(message = "User ID cannot be empty")
    private String userId;

	@JsonProperty("password")
    @NotEmpty(message = "Password cannot be empty")
    private String password;

	@JsonProperty("apiSec")
    @NotEmpty(message = "Secret Key cannot be empty")
    private String secretKey;

	@JsonProperty("authKey")
    @NotEmpty(message = "Auth Key cannot be empty")
    private String authKey;

	public String getUserApikey() {
		return userApikey;
	}

	public void setUserApikey(String userApikey) {
		this.userApikey = userApikey;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}

	public String getAuthKey() {
		return authKey;
	}

	public void setAuthKey(String authKey) {
		this.authKey = authKey;
	}
	
	public Map<String, String> toMap() {
        Map<String, String> credentials = new HashMap<>();
        credentials.put("apiKey", this.userApikey);
        credentials.put("username", this.userId);
        credentials.put("password", this.password);
        credentials.put("apiSec", this.secretKey);
        credentials.put("authKey", this.authKey);
        return credentials;
    }

	@Override
	public String toString() {
		return "AccessTokenRequest [userApikey=" + userApikey + ", userId=" + userId + ", password=" + password
				+ ", secretKey=" + secretKey + ", authKey=" + authKey + "]";
	}

    // Getters and Setters
    
}
