package com.example.escrow;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.web.bind.annotation.*;

@RestController
public class EscrowController {
    private final EscrowService escrows;
    private final DeliveryParser parser;

    public EscrowController(EscrowService escrows, DeliveryParser parser) {
        this.escrows = escrows;
        this.parser = parser;
    }

    public record CreateRequest(String seller, String amount) {}

    public record FundRequest(String txHash, String network) {}

    private static String buyer(HttpServletRequest request) {
        return (String) request.getAttribute(ApiKeyFilter.BUYER_ATTRIBUTE);
    }

    private static Map<String, Object> view(EscrowService.Escrow e) {
        return Map.of("id", e.id, "seller", e.seller, "amount", e.amount.toPlainString(),
                "status", e.status.name(), "releaseTx", e.releaseTx == null ? "" : e.releaseTx);
    }

    @PostMapping("/escrows")
    public Map<String, Object> create(@RequestBody CreateRequest body, HttpServletRequest request) {
        return view(escrows.create(buyer(request), body.seller(), body.amount()));
    }

    @PostMapping("/escrows/{id}/release")
    public Map<String, Object> release(@PathVariable long id, HttpServletRequest request) throws Exception {
        return view(escrows.release(id, buyer(request)));
    }

    @PostMapping("/escrows/{id}/fund")
    public Map<String, Object> fund(@PathVariable long id, @RequestBody FundRequest body,
                                    HttpServletRequest request) throws Exception {
        return view(escrows.fund(id, buyer(request), body.txHash(), body.network()));
    }

    @PostMapping(value = "/inbound/delivery-confirmations", consumes = "text/plain")
    public Map<String, Object> deliveryConfirmation(@RequestBody String emailBody) throws Exception {
        return view(escrows.releaseOnDelivery(parser.parse(emailBody)));
    }
}
