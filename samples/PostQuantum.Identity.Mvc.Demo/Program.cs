using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PostQuantum.Identity.DependencyInjection;
using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;

// ---------------------------------------------------------------------------
// PostQuantum.Identity — controller-based (MVC) sample. Same wiring as the
// minimal-API demo, expressed with attribute-routed controllers:
//
//   POST /account/register   { "username": "...", "password": "..." }
//   POST /account/login      { "username": "...", "password": "..." }  -> PQ token
//   GET  /me                  (Authorization: Bearer <token>)          -> [Authorize]
//
// Argon2id password hashing works on every runtime; token issuance/validation
// needs the .NET 10 BCL post-quantum primitives (OpenSSL 3.5+ on Linux).
// ---------------------------------------------------------------------------

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddDbContext<DemoIdentityContext>(o => o.UseInMemoryDatabase("pq-identity-mvc-demo"));

var identity = builder.Services
    .AddIdentityCore<IdentityUser>(o => o.Password.RequiredLength = 8)
    .AddArgon2idPasswordHasher<IdentityUser>(o => o.MemorySizeKib = 19456)
    .AddEntityFrameworkStores<DemoIdentityContext>();

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
            SignatureVerificationKey = signingKey,
            ValidIssuer = TokenConstants.Issuer,
            ValidAudience = TokenConstants.Audience,
        });
    builder.Services.AddAuthorization();
}

var app = builder.Build();

if (signingKey is not null)
{
    app.UseAuthentication();
    app.UseAuthorization();
}

app.MapControllers();
app.Run();

/// <summary>Shared issuer/audience constants for the sample.</summary>
internal static class TokenConstants
{
    public const string Issuer = "https://demo.postquantum-identity.local";
    public const string Audience = "api://mvc-demo";
}

/// <summary>EF Core Identity store for the demo (in-memory).</summary>
internal sealed class DemoIdentityContext(DbContextOptions<DemoIdentityContext> options)
    : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<IdentityUser>(options);
