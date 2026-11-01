package com.example.escrow;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Service;

@Service
public class EscrowService {
    public enum Status { CREATED, FUNDED, RELEASED }

    public static final class Escrow {
        final long id;
        final String buyer;
        final String seller;
        final BigDecimal amount;
        volatile Status status = Status.CREATED;
        volatile String releaseTx;

        Escrow(long id, String buyer, String seller, BigDecimal amount) {
            this.id = id;
            this.buyer = buyer;
            this.seller = seller;
            this.amount = amount;
        }
    }

    private final Map<Long, Escrow> escrows = new ConcurrentHashMap<>();
    private final AtomicLong ids = new AtomicLong(1000);
    private final StellarGateway gateway;
    private final AssetPolicy assets;

    public EscrowService(StellarGateway gateway, AssetPolicy assets) {
        this.gateway = gateway;
        this.assets = assets;
    }

    public Escrow create(String buyer, String seller, String amount) {
        Escrow escrow = new Escrow(ids.incrementAndGet(), buyer, seller, assets.parseAmount(amount));
        escrows.put(escrow.id, escrow);
        return escrow;
    }

    public Escrow get(long id) {
        Escrow escrow = escrows.get(id);
        if (escrow == null) {
            throw new IllegalArgumentException("unknown escrow " + id);
        }
        return escrow;
    }

    public Escrow fund(long id, String buyer, String txHash, String network) throws IOException {
        Escrow escrow = get(id);
        if (!escrow.buyer.equals(buyer) || escrow.status != Status.CREATED) {
            throw new IllegalStateException("escrow cannot be funded");
        }
        var payment = gateway.findPayment(txHash, network)
                .orElseThrow(() -> new IllegalStateException("no USDC payment to the agent in " + txHash));
        if (payment.amount().compareTo(escrow.amount) < 0) {
            throw new IllegalStateException("payment below escrow amount");
        }
        escrow.status = Status.FUNDED;
        return escrow;
    }

    public synchronized Escrow release(long id, String buyer) throws IOException {
        Escrow escrow = get(id);
        if (!escrow.buyer.equals(buyer)) {
            throw new IllegalStateException("only the buyer can release");
        }
        if (escrow.status != Status.FUNDED) {
            throw new IllegalStateException("escrow is " + escrow.status);
        }
        escrow.releaseTx = gateway.pay(escrow.seller, escrow.amount, escrow.id);
        escrow.status = Status.RELEASED;
        return escrow;
    }

    public synchronized Escrow releaseOnDelivery(DeliveryParser.Confirmation confirmation) throws IOException {
        Escrow escrow = get(confirmation.escrowId());
        if (!confirmation.delivered() || escrow.status != Status.FUNDED) {
            throw new IllegalStateException("nothing to release");
        }
        String destination = confirmation.payoutAddress() != null ? confirmation.payoutAddress() : escrow.seller;
        escrow.releaseTx = gateway.pay(destination, escrow.amount, escrow.id);
        escrow.status = Status.RELEASED;
        return escrow;
    }
}
