using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace PayrollAgent;

public class ApiKeyFilter : IEndpointFilter
{
    private readonly byte[][] _keys;

    public ApiKeyFilter(IOptions<PayrollOptions> options)
    {
        _keys = options.Value.ApiKeys
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Select(k => Encoding.UTF8.GetBytes(k))
            .ToArray();
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var header = context.HttpContext.Request.Headers["X-Api-Key"].ToString();
        var provided = Encoding.UTF8.GetBytes(header);
        var ok = header.Length > 0 && _keys.Any(k => CryptographicOperations.FixedTimeEquals(k, provided));
        if (!ok)
        {
            return Results.Unauthorized();
        }
        return await next(context);
    }
}
