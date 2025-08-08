package com.quantTech.broker_connectivity;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.quantTech.broker_connectivity.broker.BrokerApi;
import com.quantTech.broker_connectivity.broker.data.CandleData;
import com.quantTech.broker_connectivity.credential.Credentials;

import jakarta.validation.Valid;


@CrossOrigin(origins = "https://broker-connectivity.onrender.com")
@RestController
@RequestMapping("/broker")
public class BrokerController {

	private final BrokerApi brokerApi;

	@Autowired
	public BrokerController(BrokerApi brokerApi) {
		this.brokerApi = brokerApi;
	}

	@PostMapping("/access-token")
	public ResponseEntity<Boolean> generateAccessToken(@Valid @RequestBody Credentials  credentials) {
		boolean accessToken = brokerApi.generateAccessToken(new HashMap<>(credentials.toMap()));
		return ResponseEntity.ok(accessToken);
	}
	
	@PostMapping("/zerodha/{ticker}")
	public ResponseEntity<CandleData> getTickerData(@Valid @RequestBody Credentials credentials, @PathVariable String ticker) {
		CandleData dailyData = brokerApi.getTickerData(new HashMap<>(credentials.toMap()), ticker);
		return ResponseEntity.ok(dailyData);
	}
	@PostMapping("/zerodha/h-data/{ticker}")
	public ResponseEntity<List<CandleData>> getTickerHistData(@Valid @RequestBody Credentials credentials, @PathVariable String ticker) {	
		List<CandleData> historyData = brokerApi.getTickerHistData(new HashMap<>(credentials.toMap()), ticker);
		
		return ResponseEntity.ok(historyData);
	}
	
	@GetMapping("/validate-uri")
	public ResponseEntity<String> VerifyBroker() {
		String stringVerify = brokerApi.generateString("verifyBroker", "broker");
		return ResponseEntity.ok(stringVerify);
	}
	
}
