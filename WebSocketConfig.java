package com.phishguard.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.*;

/**
 * WebSocket / STOMP configuration.
 *
 * Clients connect to ws://host/ws and subscribe to:
 *   /topic/alerts/{sessionId}   — user-specific threat alerts
 *   /topic/admin/threats        — admin threat stream
 *   /topic/system               — system-wide broadcasts
 */
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/topic");          // outbound destinations
        registry.setApplicationDestinationPrefixes("/app"); // inbound from clients
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws")
                .setAllowedOriginPatterns("*")
                .withSockJS();  // SockJS fallback for browsers that don't support native WS
    }
}
