/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.co.spudsoft.tokenvalidation.nimbus;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.vertx.core.http.HttpHeaders;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.spudsoft.tokenvalidation.JwksHandler;
import uk.co.spudsoft.tokenvalidation.jdk.JdkJwksHandler;

/**
 * @author njt
 */
public class NimbusJwksHandler implements HttpHandler, Closeable, JwksHandler<NimbusTokenBuilder> {

  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(JdkJwksHandler.class);

  private static final Base64.Encoder BASE64 = Base64.getUrlEncoder().withoutPadding();
  
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private final String context = "/bob";
  private final String configUrl = context + "/.well-known/openid-configuration";
  private final String jwksUrl = context + "/jwks";
  private final String introspectUrl = context + "/protocol/openid-connect/token/introspect";

  private NimbusTokenBuilder tokenBuilder;
  private final int port;

  private final HttpServer server;
  private final Executor executor;

  @Override
  public void setTokenBuilder(NimbusTokenBuilder tokenBuilder) {
    this.tokenBuilder = tokenBuilder;
  }

  @Override
  public String getBaseUrl() {
    return "http://localhost:" + port + context;
  }

  public NimbusJwksHandler() throws IOException {
    try (ServerSocket s = new ServerSocket(0)) {
      this.port = s.getLocalPort();
    }
    executor = Executors.newFixedThreadPool(2);
    server = HttpServer.create(new InetSocketAddress(this.port), 2);
    server.setExecutor(executor);
  }

  public void start() {
    server.createContext(context, this);
    server.start();
  }

  @Override
  public void close() throws IOException {
    server.stop(1);
  }

  protected void sendResponse(HttpExchange exchange, int responseCode, String body) throws IOException {
    byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(responseCode, bodyBytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bodyBytes);
    }
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    logger.debug("handle {} {}", exchange.getRequestMethod(), exchange.getRequestURI());

    if (null == exchange.getRequestURI().getPath()) {
      sendResponse(exchange, 404, "Not found");
    } else switch (exchange.getRequestURI().getPath()) {
      case configUrl:
        handleConfigRequest(exchange);
        break;
      case jwksUrl:
        handleJwksRequest(exchange);
        break;
      case introspectUrl:
        handleIntrospectRequest(exchange);
        break;
      default:
        sendResponse(exchange, 404, "Not found");
    }
  }

  protected void handleConfigRequest(HttpExchange exchange) throws IOException {
    ObjectNode config = MAPPER.createObjectNode();
    config.put("jwks_uri", "http://localhost:" + port + jwksUrl);
    sendResponse(exchange, 200, config.toString());
  }

  protected void handleJwksRequest(HttpExchange exchange) throws IOException {
    
    Map<String, JWK> keyMap = tokenBuilder.getKeys();

    JWKSet jwkSet = new JWKSet(new ArrayList<>(keyMap.values()));
    sendResponse(exchange, 200, jwkSet.toString());
  }
  
  protected void handleIntrospectRequest(HttpExchange exchange)
          throws IOException {
    ObjectNode config = MAPPER.createObjectNode();
    config.put("bobby", "bobby value");
    exchange.getResponseHeaders().add("cache-control", "max-age=100");
    sendResponse(exchange, 200, config.toString());
  }
}
