package com.quantTech.broker_connectivity.broker.exception;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class CustomizedResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

	// You can override methods here to customize the response for specific exceptions
	// For example, you can handle AccessTokenNotGenerated exception specifically

	@ExceptionHandler(AccessTokenNotGenerated.class)
	protected ResponseEntity<Object> handleAccessTokenNotGenerated(
			AccessTokenNotGenerated ex, WebRequest request) {
		String bodyOfResponse = "Access token could not be generated: " + ex.getMessage();		
		return ResponseEntity
				.status(HttpStatus.UNAUTHORIZED)			
				.body(bodyOfResponse);
	}
	
	@ExceptionHandler(Exception.class)
	protected ResponseEntity<Object> handleGenericException(
			Exception ex, WebRequest request) {
		String bodyOfResponse = "An unexpected error occurred: " + ex.getMessage();
		return ResponseEntity
				.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body(bodyOfResponse);
	}
	
	// handle method argument not valid
	@Override
	protected ResponseEntity handleMethodArgumentNotValid(
			MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
		
			String errorStr = "";
			int countError = 1;
			for(var str : ex.getFieldErrors()) {
				
				errorStr += "Error " + countError + ": " + str.getField() + " - " + str.getDefaultMessage() + "\n";
				countError++;
			}
			ErrorDetails errorDetails = new ErrorDetails(
				java.time.LocalDateTime.now().toString(),
				"Method argument not valid",
				errorStr
			);
		String bodyOfResponse = "Method argument not valid: " + ex.getMessage();
		System.out.println("YAGNA MethodArgumentNotValidException: " + errorDetails);
		return ResponseEntity
				.status(HttpStatus.BAD_REQUEST)
				.body(errorDetails);
	}
	// Add more exception handlers as needed

}
