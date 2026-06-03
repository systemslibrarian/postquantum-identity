using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using PostQuantum.Identity.DependencyInjection;
using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;

// ---------------------------------------------------------------------------
// PostQuantum.Identity — controller-based (MVC) sample. Same production-shape
// wiring as the minimal-API demo, expressed with attribute-routed controllers:
//
//   POST /account/register   { "username": "...", "password": "..." }
//   POST /account/login      { "username": "...", "password": "..." }  -> PQ token
//   POST /account/refresh     (Authorization: Bearer <valid token>)   -> fresh token
//   POST /account/logout      (Authorization: Bearer <valid token>)   -> revoke jti
//   GET  /me                  (Authorization: Bearer <valid token>)   -> [Authorize]
//
// Argon2id password hashing works on every runtime; token issuance/validation
// needs the .NET 10 BCL post-quantum primitives (OpenSSL 3.5+ on Linux).
// ---------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddProblemDetails();
builder.Services.AddDbContext<DemoIdentityContext>(o => o.UseInMemoryDatabase("pq-identity-mvc-demo"));

// Asymmetric DoS mitigation for the Argon2id-heavy and token-issuance endpoints.
// Same fixed-window IP partition policy as the minimal-API demo; apply via
// [EnableRateLimiting("auth")] on the action methods that hit those costs.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("auth", httpContext => RateLimitPartition.GetFixedWindowLimiter(
        partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        factory: _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10,
            Window = TimeSpan.FromSeconds(30),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0,
        }));
});

IdentityBuilder identity = builder.Services
    .AddIdentityCore<IdentityUser>(o => o.Password.RequiredLength = 8)
    .AddArgon2idPasswordHasher<IdentityUser>(o => o.MemorySizeKib = 19456)
    .AddEntityFrameworkStores<DemoIdentityContext>();

// In-memory revocation list (a real service would use Redis / a DB table with TTL).
var revokedJtis = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);
builder.Services.AddSingleton(revokedJtis);

// One signing key for the process lifetime (provision/rotate out of band in prod).
MLDsa? signingKey = MLDsa.IsSupported ? MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65) : null;

if (signingKey is not null)
{
    identity.AddPostQuantumTokens<IdentityUser>(o =>
    {
        o.SigningKey = signingKey;
        o.KeyId = "mvc-demo-1";
        o.Issuer = TokenConstants.Issuer;
        o.Audience = TokenConstants.Audience;
    });

    builder.Services
        .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
        .AddPqJwtBearer(o => o.ValidationParameters = new PqJwtValidationParameters
        {
            // For the MVC sample we hold a single key; the minimal-API sample shows
            // the kid-resolver pattern for a multi-key ring.
            SignatureVerificationKey = signingKey,
            ValidIssuer = TokenConstants.Issuer,
            ValidAudience = TokenConstants.Audience,
        });
    builder.Services.AddAuthorization();
}

WebApplication app = builder.Build();

app.UseStatusCodePages();
app.UseRateLimiter();

if (signingKey is not null)
{
    app.UseAuthentication();
    // Reject any authenticated request whose token's jti has been revoked.
    app.Use(async (ctx, next) =>
    {
        if (ctx.User.Identity?.IsAuthenticated == true)
        {
            string? jti = ctx.User.FindFirst("jti")?.Value;
            if (jti is not null && revokedJtis.ContainsKey(jti))
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await ctx.Response.WriteAsJsonAsync(new
                {
                    type = "https://tools.ietf.org/html/rfc6750#section-3.1",
                    title = "Token has been revoked",
                    status = 401,
                });
                return;
            }
        }

        await next();
    });
    app.UseAuthorization();
}

app.MapControllers();
app.Run();

/// <summary>Shared issuer/audience constants for the sample.</summary>
internal static class TokenConstants
{
    public const string Issuer = "https://demo.postquantum-identity.local";
    public const string Audience = "api://mvc-demo";
    public const string CurrentKeyId = "mvc-demo-1";
}

/// <summary>EF Core Identity store for the demo (in-memory).</summary>
internal sealed class DemoIdentityContext(DbContextOptions<DemoIdentityContext> options)
    : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<IdentityUser>(options);
