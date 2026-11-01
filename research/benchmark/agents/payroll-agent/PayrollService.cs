using Microsoft.Extensions.Logging;

namespace PayrollAgent;

public record PaidLine(string ContractorId, string Amount, string TxHash);

public record BatchResult(string BatchId, List<PaidLine> Paid);

public class PayrollService(BatchValidator validator, StellarSigner signer, ILogger<PayrollService> log)
{
    public async Task<BatchResult> RunBatch(PayrollBatch batch)
    {
        var lines = validator.Validate(batch);
        var paid = new List<PaidLine>();
        foreach (var (line, amount) in lines)
        {
            var hash = await signer.Pay(line.Destination, amount, $"payroll {batch.Period}");
            log.LogInformation("batch {Batch}: paid {Contractor} {Amount} in {Hash}", batch.BatchId, line.ContractorId, amount, hash);
            paid.Add(new PaidLine(line.ContractorId, line.Amount, hash));
        }
        return new BatchResult(batch.BatchId, paid);
    }
}
