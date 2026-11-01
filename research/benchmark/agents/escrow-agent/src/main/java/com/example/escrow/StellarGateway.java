package com.example.escrow;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.stellar.sdk.KeyPair;
import org.stellar.sdk.Network;
import org.stellar.sdk.PaymentOperation;
import org.stellar.sdk.Server;
import org.stellar.sdk.Transaction;
import org.stellar.sdk.TransactionBuilder;
import org.stellar.sdk.responses.AccountResponse;
import org.stellar.sdk.responses.SubmitTransactionResponse;
import org.stellar.sdk.responses.operations.OperationResponse;
import org.stellar.sdk.responses.operations.PaymentOperationResponse;

@Component
public class StellarGateway {
    private static final String PUBLIC_HORIZON = "https://horizon.stellar.org";
    private static final String TESTNET_HORIZON = "https://horizon-testnet.stellar.org";

    private final KeyPair signer;
    private final AssetPolicy assets;
    private final Server publicServer = new Server(PUBLIC_HORIZON);

    public StellarGateway(@Value("${escrow.signing-seed}") String seed, AssetPolicy assets) {
        this.signer = KeyPair.fromSecretSeed(seed);
        this.assets = assets;
    }

    private Server serverFor(String network) {
        if ("testnet".equals(network)) {
            return new Server(TESTNET_HORIZON);
        }
        return publicServer;
    }

    public String agentAccount() {
        return signer.getAccountId();
    }

    public record IncomingPayment(String from, BigDecimal amount) {}

    public Optional<IncomingPayment> findPayment(String txHash, String network) throws IOException {
        Server server = serverFor(network);
        for (OperationResponse op : server.payments().forTransaction(txHash).execute().getRecords()) {
            if (op instanceof PaymentOperationResponse payment
                    && agentAccount().equals(payment.getTo())
                    && assets.isUsdc(payment.getAsset())) {
                return Optional.of(new IncomingPayment(payment.getFrom(), new BigDecimal(payment.getAmount())));
            }
        }
        return Optional.empty();
    }

    public String pay(String destination, BigDecimal amount, long escrowId) throws IOException {
        AccountResponse source = publicServer.accounts().account(signer.getAccountId());
        Transaction tx = new TransactionBuilder(source, Network.PUBLIC)
                .addOperation(new PaymentOperation.Builder(destination, assets.usdc(), amount.toPlainString()).build())
                .addMemo(org.stellar.sdk.Memo.id(escrowId))
                .setTimeout(180)
                .setBaseFee(Transaction.MIN_BASE_FEE * 2)
                .build();
        tx.sign(signer);
        SubmitTransactionResponse response = publicServer.submitTransaction(tx);
        if (!response.isSuccess()) {
            throw new IOException("release failed: " + response.getExtras().getResultCodes().getTransactionResultCode());
        }
        return response.getHash();
    }
}
