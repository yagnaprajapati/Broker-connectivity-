package com.quantTech.broker_connectivity.broker;

import java.util.HashMap;
import java.util.List;

import com.quantTech.broker_connectivity.broker.data.CandleData;

public interface BrokerApi {
    String BROKER_NAME = "Zerodha";
	
	public boolean connectWebsocket(String exchange, long mktStartEpoch, String manager);
	
	public boolean generateAccessToken(HashMap<String, String> credentials);

	public String generateString(String string, String string2);

	public CandleData getTickerData(HashMap<String, String> credential, String ticker);

	public List<CandleData> getTickerHistData(HashMap<String, String> hashMap, String ticker);	
}
