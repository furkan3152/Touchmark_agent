using PayrollAgent;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<PayrollOptions>(builder.Configuration.GetSection("Payroll"));
builder.Services.AddSingleton<StellarSigner>();
builder.Services.AddSingleton<BatchValidator>();
builder.Services.AddSingleton<PayrollService>();

var app = builder.Build();

var api = app.MapGroup("/").AddEndpointFilter<ApiKeyFilter>();

api.MapGet("/agent/tools/payroll-account", (StellarSigner signer) =>
    Results.Ok(new { account = signer.PublicKey, network = "public" }));

api.MapPost("/payroll/batches", async (PayrollBatch batch, PayrollService payroll) =>
{
    try
    {
        var result = await payroll.RunBatch(batch);
        return Results.Ok(result);
    }
    catch (BatchRejectedException ex)
    {
        return Results.UnprocessableEntity(new { error = ex.Message });
    }
});

api.MapPost("/agent/tools/sign-payload", (SignPayloadRequest req, StellarSigner signer) =>
{
    var payload = Convert.FromBase64String(req.PayloadBase64);
    var signature = signer.SignRaw(payload);
    return Results.Ok(new { account = signer.PublicKey, signature = Convert.ToBase64String(signature) });
});

app.Run();

public record SignPayloadRequest(string PayloadBase64, string? Partner);
