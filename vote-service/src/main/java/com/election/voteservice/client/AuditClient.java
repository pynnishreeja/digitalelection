package com.election.voteservice.client;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
public class AuditClient {

    private final RestClient restClient;
    private final String internalServiceToken;

    public AuditClient(RestClient restClient,
                       @Value("${internal.service.token}") String internalServiceToken) {
        this.restClient = restClient;
        this.internalServiceToken = internalServiceToken;
    }

    public void recordVote(String eventData) {

        restClient.post()
                .header("X-Internal-Service-Token", internalServiceToken)
                .uri(uriBuilder -> uriBuilder
                        .scheme("http")
                        .host("localhost")
                        .port(8084)
                        .path("/api/audit")
                        .queryParam("eventType", "VOTE_CAST")
                        .queryParam("eventData", eventData)
                        .build())
                .retrieve()
                .toBodilessEntity();
    }
}