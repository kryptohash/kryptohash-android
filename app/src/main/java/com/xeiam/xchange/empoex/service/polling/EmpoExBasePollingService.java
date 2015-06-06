package com.xeiam.xchange.empoex.service.polling;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import si.mazi.rescu.ClientConfig;
import si.mazi.rescu.ParamsDigest;
import si.mazi.rescu.RestProxyFactory;

import com.xeiam.xchange.Exchange;
import com.xeiam.xchange.currency.CurrencyPair;
import com.xeiam.xchange.empoex.EmpoEx;
import com.xeiam.xchange.empoex.EmpoExAuthenticated;
import com.xeiam.xchange.empoex.EmpoExUtils;
import com.xeiam.xchange.empoex.dto.marketdata.EmpoExTicker;
import com.xeiam.xchange.empoex.service.EmpoExHmacPostBodyDigest;
import com.xeiam.xchange.empoex.service.EmpoExPayloadDigest;
import com.xeiam.xchange.service.BaseExchangeService;
import com.xeiam.xchange.service.polling.BasePollingService;
import com.xeiam.xchange.service.streaming.SSLSocketFactoryEx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import de.schildbach.wallet.Constants;
import android.os.Build;

public class EmpoExBasePollingService extends BaseExchangeService implements BasePollingService {

  protected final String apiKey;
  protected final EmpoExAuthenticated empoExAuthenticated;
  protected final ParamsDigest signatureCreator;
  protected final ParamsDigest payloadCreator;

  protected final EmpoEx empoEx;
  private static final Logger log = LoggerFactory.getLogger(EmpoExBasePollingService.class);
  private static boolean ENABLE_TLSv1_2 = Build.VERSION.SDK_INT >= Constants.SDK_LOLLIPOP;

  /**
   * Constructor
   *
   * @param exchange
   */
  public EmpoExBasePollingService(Exchange exchange) {
    super(exchange);

    SSLSocketFactory sf = null;
    if (ENABLE_TLSv1_2) {
        // Only API 21 and later (Lollipop) provide the TLS 1.2 cipher suites.
	    try {
	        SSLContext context = SSLContext.getInstance("TLSv1.2");
	        context.init(null, null, null);
	        sf = new SSLSocketFactoryEx(context.getSocketFactory());
	    } catch (final Exception e) {
	        // swallow
        }
    }
    if (sf != null) {
        ClientConfig myconfig = new ClientConfig();
        myconfig.setSslSocketFactory(sf);
        this.empoExAuthenticated = RestProxyFactory.createProxy(EmpoExAuthenticated.class, exchange.getExchangeSpecification().getSslUri(), myconfig);
    } else {
        this.empoExAuthenticated = RestProxyFactory.createProxy(EmpoExAuthenticated.class, exchange.getExchangeSpecification().getSslUri());
    }
    this.apiKey = exchange.getExchangeSpecification().getApiKey();
    this.signatureCreator = EmpoExHmacPostBodyDigest.createInstance(exchange.getExchangeSpecification().getSecretKey());
    this.payloadCreator = new EmpoExPayloadDigest();
    if (sf != null) {
        ClientConfig myconfig = new ClientConfig();
        myconfig.setSslSocketFactory(sf);
        this.empoEx = RestProxyFactory.createProxy(EmpoEx.class, exchange.getExchangeSpecification().getSslUri(), myconfig);
    } else {
        this.empoEx = RestProxyFactory.createProxy(EmpoEx.class, exchange.getExchangeSpecification().getSslUri());
    }
  }

  @Override
  public List<CurrencyPair> getExchangeSymbols() throws IOException {

    List<CurrencyPair> currencyPairs = new ArrayList<CurrencyPair>();

    List<EmpoExTicker> tickers = empoExAuthenticated.getEmpoExTickers();

    for (EmpoExTicker ticker : tickers) {
      currencyPairs.add(EmpoExUtils.toCurrencyPair(ticker.getPairname()));
    }
    return currencyPairs;
  }
}
