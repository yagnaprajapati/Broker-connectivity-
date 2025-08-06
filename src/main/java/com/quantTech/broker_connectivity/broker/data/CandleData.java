package com.quantTech.broker_connectivity.broker.data;

public class CandleData {

	private String time;
    private double open, high, low, close, volume;
    public CandleData(String time, double open, double high, double low, double close, double volume) {
        this.time = time;
        this.open = open;
        this.high = high;
        this.low = low;
        this.close = close;
        this.volume = volume;
    }

    public CandleData(double open, double high, double low, double close, double volume) {
        this.open = open;
        this.high = high;
        this.low = low;
        this.close = close;
        this.volume = volume;
    }
    
    

    public String getTime() {
		return time;
	}



	public void setTime(String time) {
		this.time = time;
	}



	public double getOpen() {
		return open;
	}



	public void setOpen(double open) {
		this.open = open;
	}



	public double getHigh() {
		return high;
	}



	public void setHigh(double high) {
		this.high = high;
	}



	public double getLow() {
		return low;
	}



	public void setLow(double low) {
		this.low = low;
	}



	public double getClose() {
		return close;
	}



	public void setClose(double close) {
		this.close = close;
	}



	public double getVolume() {
		return volume;
	}



	public void setVolume(double volume) {
		this.volume = volume;
	}



	@Override
    public String toString() {
        return String.format("Time: %s, O: %.2f, H: %.2f, L: %.2f, C: %.2f, V: %.0f",
                time, open, high, low, close, volume);
    }
}
