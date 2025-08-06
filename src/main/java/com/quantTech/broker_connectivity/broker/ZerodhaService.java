package com.quantTech.broker_connectivity.broker;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import com.quantTech.broker_connectivity.broker.data.CandleData;

import jakarta.annotation.PostConstruct;

@Service
@Primary
public class ZerodhaService implements BrokerApi {

	public Map<String, Integer> instrumentMap = new HashMap<>();
	public ZerodhaKiteApi kiteApi;

	@Autowired
	private ZerodhaService(ZerodhaKiteApi kiteApi) {
		System.out.println("This is ZerodhaService: Initializing ZerodhaKiteApi");
		this.kiteApi = kiteApi;
	}
	
	@PostConstruct
    public void initInstrumentMap() {
        System.out.println("This is ZerodhaService: Initializing ZerodhaKiteApi instrument map...");
        instrumentMap = this.kiteApi.loadInstrumentTokenMap();
        System.out.println("This is ZerodhaService: Instrument map loaded with " + instrumentMap.size() + " instruments.");
    }

	@Override
	public boolean connectWebsocket(String exchange, long mktStartEpoch, String manager) {
		// Implementation for connecting to Zerodha's WebSocket
		System.out.println("Connecting to Zerodha WebSocket for exchange: " + exchange);
		return true; // Placeholder for actual connection logic
	}

	@Override
	public boolean generateAccessToken(HashMap<String, String> credential) {
		System.out.println("Thisi is ZerodhaService: Generating access token with credentials: " + credential);
		String accessToken = kiteApi.getAccessToken(credential);
		if (accessToken == null || accessToken.isEmpty()) {
			System.out.println("Failed to generate access token.");
			return false;
		}
		return true;
	}

	@Override
	public String generateString(String string, String string2) {
		// TODO Auto-generated method stub
		return "This is a string from ZerodhaService: " + string + " and " + string2;
	}

	@Override
	public CandleData getTickerData(HashMap<String, String> credential, String ticker) {
		// TODO Auto-generated method stub
		System.out.println("Thisi is ZerodhaService: Generating access token with credentials: " + credential);
		String accessToken = kiteApi.getAccessToken(credential);
		if (accessToken == null || accessToken.isEmpty()) {
			System.out.println("Failed to generate access token.");
			return null;
		} else {
			ticker = ticker.toUpperCase();
			System.out.println("Successfully generated access token: " + accessToken);
			System.out.println("Fetching OHLC data for ticker: " + ticker);
			System.out.println("Using API Key: " + credential.get("apiKey"));
			// Assuming the kiteApi has a method to fetch OHLC data
			CandleData ohlcData = kiteApi.getOHLCData(ticker, credential.get("apiKey"), accessToken);
			if (ohlcData != null) {
				System.out.println("Successfully fetched OHLC data for ticker: " + ticker);
				return ohlcData;
			} else {
				System.out.println("Failed to fetch OHLC data for ticker: " + ticker);
			}
		}

		return null;
	}

	@Override
	public List<CandleData> getTickerHistData(HashMap<String, String> credential, String ticker) {
		// TODO Auto-generated method stub
		// TODO Auto-generated method stub
		System.out.println("Thisi is ZerodhaService: Generating access token with credentials: " + credential);
		String accessToken = kiteApi.getAccessToken(credential);
		if (accessToken == null || accessToken.isEmpty()) {
			System.out.println("Failed to generate access token.");
			return null;
		} else {
			ticker = ticker.toUpperCase();
			String apiKey = credential.get("apiKey");
			System.out.println("Using API ticker: " + ticker);
			System.out.println("instrumentMap size: " + instrumentMap.size());
			
			//boolean final isFind = true;
			String finalTicker = "NSE:" +ticker;
			instrumentMap.forEach((key, value) -> {
				if(key.equals(finalTicker)) {
					System.out.println("Found instrument token for ticker: " + key + " - Token: " + value);
					//isFind = true;
				}
				System.out.println("Instrument: " + key + ", Token: " + value);
			});
//			if(isFind == false) {
//				System.out.println("Ticker not found in instrumentMap: " + ticker);
//				return null;
//			}
//			else {
//				System.out.println("Ticker found in instrumentMap: " + ticker);
			//}
			
			int instrumentToken = instrumentMap.get(finalTicker);
			String interval = "5minute";
	        String fromDate = "2025-08-01";
	        String toDate = "2025-08-02";
			System.out.println("Successfully generated access token: " + accessToken);
			System.out.println("Fetching OHLC data for ticker: " + ticker);
			System.out.println("Using API Key: " + credential.get("apiKey"));
			// Assuming the kiteApi has a method to fetch OHLC data
			CandleData ohlcData = kiteApi.getOHLCData(ticker, apiKey, accessToken);
			List<CandleData> historyData = kiteApi.getHistoricalData(apiKey, accessToken, instrumentToken, interval, fromDate, toDate);
			if (historyData != null) {
				System.out.println("Successfully fetched OHLC data for ticker: " + ticker);
				return historyData;
			} else {
				System.out.println("Failed to fetch OHLC data for ticker: " + ticker);
			}
		}
		return null;
	}
}
