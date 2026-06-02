using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PostQuantum.Identity.DependencyInjection;
using PostQuantum.Identity.Tokens;
using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;

// ---------------------------------------------------------------------------
// PostQuantum.Identity demo — real ASP.NET Core Identity, Argon2id password
// hashing, and post-quantum hybrid token issuance + validation through the
// PqJwtBearer authentication pipeline (with kid-based key rotation).
//
//   POST /register  { "username": "...", "password": "..." }  -> creates a user
//   POST /login     { "username": "...", "password": "..." }  -> returns a PQ token
//   GET  /me        (Authorization: Bearer <token>)           -> [Authorize]'d claims
//
// Passwords are hashed with Argon2id on every supported runtime. Token features
// need the .NET 10 BCL post-quantum primitives (ML-DSA-65), which require
// OpenSSL 3.5+ on Linux. Where ML-DSA is unavailable the app still runs and
// hashes passwords; the token endpoints report PQC is unavailable.
// ---------------------------------------------------------------------------

const string Issuer = "https://demo.postquantum-identity.local";
const string Audience = "api://demo";

var builder = WebApplication.CreateBuilder(args);

// In-memory EF store so the sample needs no database setup.
builder.Services.AddDbContext<DemoIdentityContext>(o => o.UseInMemoryDatabase("pq-identity-demo"));

IdentityBuilder identity = builder.Services
    .AddIdentityCore<IdentityUser>(o =>
    {
        o.Password.RequiredLength = 8;
        o.User.RequireUniqueEmail = false;
    })
    // Argon2id replaces the default PBKDF2 hasher. A lighter memory cost keeps the
    // demo snappy; production should use Argon2idOptions.Recommended (64 MiB).
    // (For an existing store, swap this for AddArgon2idPasswordHasherWithMigration.)
    .AddArgon2idPasswordHasher<IdentityUser>(o => o.MemorySizeKib = 19456)
    .AddEntityFrameworkStores<DemoIdentityContext>();

// --- Key ring (demonstrates kid-based rotation) ---------------------------
// Two ML-DSA-65 keys: "k1" (previous) and "k2" (current). New tokens are signed
// with the current key and stamped with its kid; tokens signed by EITHER key
// still validate, because the verifier resolves the right public key by kid.
// In production these are provisioned/rotated out of band and verifiers hold
// only the public halves.
var keyRing = new Dictionary<string, MLDsa>(StringComparer.Ordinal);
const string CurrentKeyId = "k2";

if (MLDsa.IsSupported)
{
    keyRing["k1"] = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    keyRing["k2"] = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

    identity.AddPostQuantumTokens<IdentityUser>(o =>
    {
        o.SigningKey = keyRing[CurrentKeyId];
        o.KeyId = CurrentKeyId;            // stamped into the token's `kid` header
        o.Issuer = Issuer;
        o.Audience = Audience;
        o.Lifetime = TimeSpan.FromHours(1);
    });

    // Validate incoming tokens with the standard auth pipeline. The resolver maps
    // the token's `kid` to the matching verification key, so rotation is seamless.
    builder.Services
        .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
        .AddPqJwtBearer(o =>
        {
            o.ValidationParameters = new PqJwtValidationParameters
            {
                SignatureKeyResolver = kid => kid is not null && keyRing.TryGetValue(kid, out MLDsa? key) ? key : null,
                ValidIssuer = Issuer,
                ValidAudience = Audience,
            };
        });
    builder.Services.AddAuthorization();
}

var app = builder.Build();

if (MLDsa.IsSupported)
{
    app.UseAuthentication();
    app.UseAuthorization();
}

app.MapGet("/", () => Results.Ok(new
{
    service = "PostQuantum.Identity demo",
    pqcAvailable = MLDsa.IsSupported,
    currentKeyId = CurrentKeyId,
    endpoints = new[] { "POST /register", "POST /login", "GET /me" },
}));

app.MapPost("/register", async (Credentials creds, UserManager<IdentityUser> users) =>
{
    var user = new IdentityUser { UserName = creds.Username };
    IdentityResult result = await users.CreateAsync(user, creds.Password);
    return result.Succeeded
        ? Results.Ok(new { message = "registered", user.Id })
        : Results.BadRequest(new { errors = result.Errors.Select(e => e.Description) });
});

app.MapPost("/login", async (
    Credentials creds,
    UserManager<IdentityUser> users,
    IPostQuantumTokenService<IdentityUser>? tokens) =>
{
    IdentityUser? user = await users.FindByNameAsync(creds.Username);
    if (user is null || !await users.CheckPasswordAsync(user, creds.Password))
    {
        // Identical response for "no such user" and "wrong password".
        return Results.Unauthorized();
    }

    if (tokens is null)
    {
        return Results.Json(
            new { error = "Post-quantum token issuance unavailable (ML-DSA needs OpenSSL 3.5+)." },
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    string token = await tokens.CreateTokenAsync(user);
    return Results.Ok(new { token, token_type = "PQ-JWT (ML-DSA-65)", kid = CurrentKeyId });
});

// Protected by the PqJwtBearer scheme: the handler validates the token (resolving
// the key by kid) and populates HttpContext.User before this runs.
app.MapGet("/me", (HttpContext ctx) => Results.Ok(new
{
    subject = ctx.User.FindFirst("sub")?.Value,
    name = ctx.User.FindFirst("name")?.Value,
    roles = ctx.User.FindAll("role").Select(c => c.Value).ToArray(),
})).RequireAuthorization();

app.Run();

/// <summary>Login/registration request body.</summary>
internal sealed record Credentials(string Username, string Password);

/// <summary>EF Core Identity store for the demo (in-memory).</summary>
internal sealed class DemoIdentityContext(DbContextOptions<DemoIdentityContext> options)
    : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<IdentityUser>(options);
