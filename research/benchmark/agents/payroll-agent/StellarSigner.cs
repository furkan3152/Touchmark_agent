using Microsoft.Extensions.Options;
using stellar_dotnet_sdk;

namespace PayrollAgent;

public class StellarSigner
{
    private readonly KeyPair _keyPair;
    private readonly Server _server;
    private readonly Asset _usdc;

    public StellarSigner(IOptions<PayrollOptions> options)
    {
        Network.UsePublicNetwork();
        _server = new Server("https://horizon.stellar.org");
        _keyPair = KeyPair.FromSecretSeed(Environment.GetEnvironmentVariable("PAYROLL_SEED")
            ?? throw new InvalidOperationException("PAYROLL_SEED is not set"));
        _usdc = Asset.CreateNonNativeAsset("USDC", options.Value.UsdcIssuer);
    }

    public string PublicKey => _keyPair.AccountId;

    public byte[] SignRaw(byte[] payload) => _keyPair.Sign(payload);

    public async Task<string> Pay(string destination, decimal amount, string memo)
    {
        var account = await _server.Accounts.Account(_keyPair.AccountId);
        var payment = new PaymentOperation.Builder(
                KeyPair.FromAccountId(destination), _usdc, amount.ToString("0.#######", System.Globalization.CultureInfo.InvariantCulture))
            .Build();
        var tx = new TransactionBuilder(account)
            .AddOperation(payment)
            .AddMemo(Memo.Text(memo.Length > 28 ? memo[..28] : memo))
            .AddTimeBounds(new TimeBounds(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(3)))
            .Build();
        tx.Sign(_keyPair);
        var response = await _server.SubmitTransaction(tx);
        if (!response.IsSuccess())
        {
            throw new InvalidOperationException($"payment to {destination} failed: {response.SubmitTransactionResponseExtras?.ExtrasResultCodes?.TransactionResultCode}");
        }
        return response.Hash;
    }
}
