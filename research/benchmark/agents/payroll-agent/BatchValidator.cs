using System.Globalization;
using Microsoft.Extensions.Options;

namespace PayrollAgent;

public class PayrollOptions
{
    public string[] ApiKeys { get; set; } = Array.Empty<string>();
    public string AllowedDestinations { get; set; } = "*";
    public decimal MaxPerLine { get; set; } = 7500m;
    public decimal MaxPerBatch { get; set; } = 60000m;
    public string UsdcIssuer { get; set; } = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
}

public record PayrollLine(string ContractorId, string Destination, string Amount);

public record PayrollBatch(string BatchId, string Period, List<PayrollLine> Lines);

public class BatchRejectedException(string message) : Exception(message);

public class BatchValidator
{
    private readonly PayrollOptions _options;
    private readonly HashSet<string> _allowed;

    public BatchValidator(IOptions<PayrollOptions> options)
    {
        _options = options.Value;
        _allowed = _options.AllowedDestinations
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.Ordinal);
    }

    public IReadOnlyList<(PayrollLine Line, decimal Amount)> Validate(PayrollBatch batch)
    {
        if (batch.Lines.Count == 0 || batch.Lines.Count > 200)
        {
            throw new BatchRejectedException("batch must contain 1-200 lines");
        }

        var result = new List<(PayrollLine, decimal)>();
        decimal total = 0;
        foreach (var line in batch.Lines)
        {
            if (!decimal.TryParse(line.Amount, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var amount)
                || amount <= 0 || decimal.Round(amount, 7) != amount)
            {
                throw new BatchRejectedException($"invalid amount for {line.ContractorId}");
            }
            if (amount > _options.MaxPerLine)
            {
                throw new BatchRejectedException($"{line.ContractorId} exceeds the per-line limit");
            }
            total += amount;
            if (total > _options.MaxPerBatch)
            {
                throw new BatchRejectedException("batch exceeds the batch limit");
            }

            CheckDestination(line);
            result.Add((line, amount));
        }
        return result;
    }

    private void CheckDestination(PayrollLine line)
    {
        if (_allowed.Contains("*"))
        {
            return;
        }
        if (!_allowed.Contains(line.Destination))
        {
            throw new BatchRejectedException($"{line.Destination} is not an approved contractor address");
        }
    }
}
