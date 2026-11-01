package com.example.escrow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class DeliveryParser {
    private static final String PROMPT = """
            You read replies to marketplace delivery e-mails. Return JSON with fields
            escrow_id (number), delivered (boolean) and payout_address (the Stellar address
            the seller asked to be paid to, or null if none is mentioned).
            """;

    public record Confirmation(long escrowId, boolean delivered, String payoutAddress) {}

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();
    private final String apiKey;

    public DeliveryParser(@Value("${openai.api-key}") String apiKey) {
        this.apiKey = apiKey;
    }

    public Confirmation parse(String emailBody) throws Exception {
        String request = mapper.writeValueAsString(mapper.createObjectNode()
                .put("model", "gpt-4o-mini")
                .set("messages", mapper.createArrayNode()
                        .add(mapper.createObjectNode().put("role", "system").put("content", PROMPT))
                        .add(mapper.createObjectNode().put("role", "user").put("content", emailBody))));
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create("https://api.openai.com/v1/chat/completions"))
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(request)).build(), HttpResponse.BodyHandlers.ofString());
        JsonNode content = mapper.readTree(mapper.readTree(response.body())
                .at("/choices/0/message/content").asText());
        String address = content.path("payout_address").isTextual() ? content.get("payout_address").asText() : null;
        return new Confirmation(content.path("escrow_id").asLong(), content.path("delivered").asBoolean(), address);
    }
}
