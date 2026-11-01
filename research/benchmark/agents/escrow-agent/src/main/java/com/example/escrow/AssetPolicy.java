package com.example.escrow;

import java.math.BigDecimal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.stellar.sdk.Asset;
import org.stellar.sdk.AssetTypeCreditAlphaNum;

@Component
public class AssetPolicy {
    private final Asset usdc;

    public AssetPolicy(@Value("${escrow.usdc-issuer:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN}") String issuer) {
        this.usdc = Asset.createNonNativeAsset("USDC", issuer);
    }

    public Asset usdc() {
        return usdc;
    }

    public boolean isUsdc(Asset asset) {
        if (!(asset instanceof AssetTypeCreditAlphaNum credit)) {
            return false;
        }
        AssetTypeCreditAlphaNum expected = (AssetTypeCreditAlphaNum) usdc;
        return expected.getCode().equals(credit.getCode())
                && expected.getIssuer().equals(credit.getIssuer());
    }

    public BigDecimal parseAmount(String amount) {
        BigDecimal value = new BigDecimal(amount);
        if (value.signum() <= 0 || value.scale() > 7) {
            throw new IllegalArgumentException("invalid amount " + amount);
        }
        return value;
    }
}
