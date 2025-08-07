package com.quantTech.broker_connectivity.broker.exception;

import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = org.springframework.http.HttpStatus.UNAUTHORIZED)
public class AccessTokenNotGenerated extends RuntimeException {
		
	private static final long serialVersionUID = 1L;

	public AccessTokenNotGenerated(String message) {
		super(message);
		System.out.println("AccessTokenNotGenerated exception: " + message);		
	}

	public AccessTokenNotGenerated(String message, Throwable cause) {
		super(message, cause);
	}

	public AccessTokenNotGenerated(Throwable cause) {
		super(cause);
	}
}
