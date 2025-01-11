package com.evryword.spring_websockets;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;

import static org.springframework.security.config.Customizer.withDefaults;

@Log4j2
@CrossOrigin
@SpringBootApplication
public class SpringWebsocketsApplication {
	@Value("${charging-station.id}")
	private String chargingStationId;

	@Value("${charging-station.password}")
	private String stationPassword;

	public static void main(String[] args) {
		SpringApplication.run(SpringWebsocketsApplication.class, args);
	}

	@RestController
	@RequestMapping(value = "/")
	public class TestController {
		@GetMapping()
		public String testRoute() {
			return "Hello from " + chargingStationId + "!!!";
		}
	}

	@CrossOrigin
	@Controller
	@Log4j2
	public static class WsController {
		@MessageMapping("/{chargingStationId}")
		@SendTo("/{chargingStationId}")
		public String send(
				@DestinationVariable("chargingStationId") String chargingStationId,
				@Payload String data) {
			log.info("chargingStationId: {}, data: {}", chargingStationId, data);
			return new SimpleDateFormat("HH:mm").format(new Date());
		}
	}

	@Configuration
	@EnableWebSocketMessageBroker
	public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {
		@Override
		public void configureMessageBroker(MessageBrokerRegistry config) {
			config.enableSimpleBroker("/");
			config.setApplicationDestinationPrefixes("/");
		}

		@Override
		public void registerStompEndpoints(StompEndpointRegistry registry) {
			registry.addEndpoint("/" + chargingStationId)
					.setAllowedOrigins("http://localhost:8080")
					.setAllowedOriginPatterns("*");
			registry.addEndpoint("/" + chargingStationId)
					.setAllowedOrigins("http://localhost:8080")
					.setAllowedOriginPatterns("*")
					.withSockJS();
		}
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				// https://docs.spring.io/spring-security/reference/features/exploits/http.html
				// https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/index.html", "/error")
						.permitAll()
						.anyRequest()
						//https://www.baeldung.com/spring-security-authorizationmanager
						.access(customAuthManager())
				)
				// if Spring MVC is on classpath and no CorsConfigurationSource is provided,
				// Spring Security will use CORS configuration provided to Spring MVC
				//.csrf(AbstractHttpConfigurer::disable)
				.cors(withDefaults());

		return http.build();
	}

	public AuthorizationManager<RequestAuthorizationContext> customAuthManager() {
		return (authentication, object) -> {
            // make authorization decision
			final var request = object.getRequest();
			final var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

			if (authorizationHeader == null) return new AuthorizationDecision(false);

			final var headerValue = authorizationHeader.split(" ");

			if (headerValue.length != 2) return new AuthorizationDecision(false);

			final var encodedValue = headerValue[1];
			final var decodedValue = new String(Base64.getDecoder().decode(encodedValue));

			log.info("decodedValue: {}", decodedValue);

			final var basicValue = decodedValue.split(":");

			if (basicValue.length != 2) return new AuthorizationDecision(false);

			final var boxId = basicValue[0];
			final var password = basicValue[1];

			log.info("url: {}", object.getRequest().getRequestURL());
			log.info("Authorization: Basic {}:{}", boxId, password);

			final var isAuthenticated = Objects.equals(chargingStationId, boxId) &&
                    Objects.equals(password, stationPassword);

            authentication.get()
                    .setAuthenticated(isAuthenticated);

            return new AuthorizationDecision(isAuthenticated);
        };
	}
}
