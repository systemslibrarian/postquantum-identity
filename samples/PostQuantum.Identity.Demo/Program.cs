using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PostQuantum.Identity.DependencyInjection;
using PostQuantum.Identity.Tokens;
using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;

// ---------------------------------------------------------------------------
// PostQuantum.Identity demo — a production-shaped reference application showing
// how ASP.NET Core Identity + Argon2id + post-quantum hybrid tokens come
// together. The wiring here is intentionally close to what a real service
// would do; only the user store (in-memory EF) and the key generation (random
// per process) are demo conveniences.
//
//   POST /register   { "username": "...", "password": "..." }   -> create user
//   POST /login      { "username": "...", "password": "..." }   -> PQ token + kid
//   POST /refresh    (Authorization: Bearer <valid token>)      -> fresh PQ token
//   POST /logout     (Authorization: Bearer <valid token>)      -> revoke jti
//   GET  /me         (Authorization: Bearer <valid token>)      -> [Authorize]
//   GET  /.well-known/pq-jwks                                   -> public keys
//
// Passwords are hashed with Argon2id on every supported runtime. Token features
// need the .NET 10 BCL post-quantum primitives (ML-DSA-65), which require
// OpenSSL 3.5+ on Linux. Where ML-DSA is unavailable the app still runs and
// hashes passwords; the token endpoints report PQC is unavailable with 503.
// ---------------------------------------------------------------------------

const string Issuer = "https://demo.postquantum-identity.local";
const string Audience = "api://demo";
string[] Endpoints =
[
    "POST /register",
    "POST /login",
    "POST /refresh",
    "POST /logout",
    "GET /me",
    "GET /.well-known/pq-jwks",
];

var builder = WebApplication.CreateBuilder(args);

// In-memory EF store so the sample needs no database setup.
builder.Services.AddDbContext<DemoIdentityContext>(o => o.UseInMemoryDatabase("pq-identity-demo"));

// Centralized ProblemDetails so error responses are RFC 7807-shaped and consistent.
builder.Services.AddProblemDetails();

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

// In-memory revocation list. A real service would back this by Redis / a DB
// table with a TTL matching the token lifetime. The contract here — "is this
// jti revoked?" — is the same regardless of the backing store.
var revokedJtis = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);
builder.Services.AddSingleton(revokedJtis);

// --- Key ring (demonstrates kid-based rotation) ---------------------------
// Two ML-DSA-65 keys: "k1" (previous) and "k2" (current). New tokens are signed
// with the current key and stamped with its kid; tokens signed by EITHER key
// still validate, because the verifier resolves the right public key by kid.
// In production these are provisioned/rotated out of band and verifiers hold
// only the public halves.
var signingKeyRing = new Dictionary<string, MLDsa>(StringComparer.Ordinal);
var verifyingKeyRing = new Dictionary<string, MLDsa>(StringComparer.Ordinal);
const string CurrentKeyId = "k2";

if (MLDsa.IsSupported)
{
    foreach (string kid in new[] { "k1", CurrentKeyId })
    {
        MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        signingKeyRing[kid] = key;
        verifyingKeyRing[kid] = MLDsa.ImportSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo());
    }

    identity.AddPostQuantumTokens<IdentityUser>(o =>
    {
        o.SigningKey = signingKeyRing[CurrentKeyId];
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
                SignatureKeyResolver = kid => kid is not null && verifyingKeyRing.TryGetValue(kid, out MLDsa? key) ? key : null,
                ValidIssuer = Issuer,
                ValidAudience = Audience,
            };
        });
    builder.Services.AddAuthorization();
}

var app = builder.Build();

app.UseStatusCodePages();

if (MLDsa.IsSupported)
{
    app.UseAuthentication();
    // Revocation middleware: rejects any authenticated request whose token's jti
    // is on the revocation list. Runs after authentication so HttpContext.User
    // is populated, but before authorization makes its decision.
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

// Service discovery / health.
app.MapGet("/", () => Results.Ok(new
{
    service = "PostQuantum.Identity demo",
    pqcAvailable = MLDsa.IsSupported,
    currentKeyId = CurrentKeyId,
    endpoints = Endpoints,
}));

// --- Registration --------------------------------------------------------
// Hashes the password with Argon2id under the hood and persists the PHC string.
// Identity surfaces every validation failure (length, alphabet, uniqueness, …)
// as a structured ProblemDetails response so callers can react meaningfully.
app.MapPost("/register", async (Credentials creds, UserManager<IdentityUser> users) =>
{
    if (creds is null || string.IsNullOrWhiteSpace(creds.Username) || string.IsNullOrWhiteSpace(creds.Password))
    {
        return Results.Problem(
            title: "Username and password are required.",
            statusCode: StatusCodes.Status400BadRequest);
    }

    var user = new IdentityUser { UserName = creds.Username };
    IdentityResult result = await users.CreateAsync(user, creds.Password);
    if (result.Succeeded)
    {
        return Results.Ok(new { message = "registered", user.Id });
    }

    return Results.ValidationProblem(
        result.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()),
        title: "Registration failed",
        statusCode: StatusCodes.Status400BadRequest);
});

// --- Login ---------------------------------------------------------------
// Verifies the password (Argon2id, fail-closed) and issues a fresh PQ-JWT.
// Identical 401 response for "no such user" and "wrong password" so the
// endpoint doesn't leak account enumeration.
app.MapPost("/login", async (
    Credentials creds,
    UserManager<IdentityUser> users,
    IPostQuantumTokenService<IdentityUser>? tokens) =>
{
    if (creds is null || string.IsNullOrWhiteSpace(creds.Username) || string.IsNullOrWhiteSpace(creds.Password))
    {
        return Results.Problem(
            title: "Username and password are required.",
            statusCode: StatusCodes.Status400BadRequest);
    }

    IdentityUser? user = await users.FindByNameAsync(creds.Username);
    if (user is null || !await users.CheckPasswordAsync(user, creds.Password))
    {
        return Results.Unauthorized();
    }

    if (tokens is null)
    {
        return Results.Problem(
            title: "Post-quantum token issuance unavailable (ML-DSA needs OpenSSL 3.5+).",
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    string token = await tokens.CreateTokenAsync(user);
    return Results.Ok(new
    {
        token,
        token_type = "PQ-JWT",
        alg = "ML-DSA-65",
        kid = CurrentKeyId,
        expires_in = (int)TimeSpan.FromHours(1).TotalSeconds,
    });
});

// --- Refresh -------------------------------------------------------------
// Issues a new token for the current authenticated subject. The classic
// "rotate before expiry" pattern — clients call /refresh a couple of minutes
// before exp and replace their stored token. The OLD jti is revoked so a
// stolen near-expiry token cannot be silently re-used after refresh.
app.MapPost("/refresh", [Authorize] async (
    HttpContext ctx,
    UserManager<IdentityUser> users,
    IPostQuantumTokenService<IdentityUser>? tokens) =>
{
    if (tokens is null)
    {
        return Results.Problem(
            title: "Post-quantum token issuance unavailable.",
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    string? subject = ctx.User.FindFirst("sub")?.Value;
    IdentityUser? user = subject is null ? null : await users.FindByIdAsync(subject);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    string? oldJti = ctx.User.FindFirst("jti")?.Value;
    if (oldJti is not null)
    {
        revokedJtis[oldJti] = DateTimeOffset.UtcNow;
    }

    string newToken = await tokens.CreateTokenAsync(user);
    return Results.Ok(new
    {
        token = newToken,
        token_type = "PQ-JWT",
        alg = "ML-DSA-65",
        kid = CurrentKeyId,
        rotated_from = oldJti,
    });
});

// --- Logout --------------------------------------------------------------
// Adds the current token's jti to the revocation list so it cannot be used
// again before its natural expiry. Idempotent — repeated calls succeed.
app.MapPost("/logout", [Authorize] (HttpContext ctx) =>
{
    string? jti = ctx.User.FindFirst("jti")?.Value;
    if (jti is not null)
    {
        revokedJtis[jti] = DateTimeOffset.UtcNow;
    }

    return Results.Ok(new { message = "logged out", revoked_jti = jti });
});

// --- /me -----------------------------------------------------------------
// Protected by the PqJwtBearer scheme: the handler validates the token (resolving
// the key by kid), the revocation middleware checks the jti, and HttpContext.User
// is populated before this runs.
app.MapGet("/me", [Authorize] (HttpContext ctx) => Results.Ok(new
{
    subject = ctx.User.FindFirst("sub")?.Value,
    name = ctx.User.FindFirst("name")?.Value,
    roles = ctx.User.FindAll("role").Select(c => c.Value).ToArray(),
    jti = ctx.User.FindFirst("jti")?.Value,
    expiresAt = ctx.User.FindFirst("exp")?.Value,
}));

// --- Public-key discovery ------------------------------------------------
// Exposes the ML-DSA-65 verification keys so a downstream service can fetch
// them and validate independently. Format: a minimal JWKS-shaped document
// (PQC JWKS is still under standards discussion; the shape here is documented
// as `pq-jwks` rather than `jwks` to avoid implying RFC 7517 strict compliance).
app.MapGet("/.well-known/pq-jwks", () =>
{
    if (!MLDsa.IsSupported)
    {
        return Results.Problem(
            title: "Post-quantum keys unavailable.",
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    var keys = verifyingKeyRing.Select(kvp => new
    {
        kid = kvp.Key,
        kty = "AKP",            // Algorithm Key Pair (draft, IETF JOSE PQC)
        alg = "ML-DSA-65",
        use = "sig",
        spki_b64 = Convert.ToBase64String(kvp.Value.ExportSubjectPublicKeyInfo()),
    });

    return Results.Ok(new { keys, current_kid = CurrentKeyId });
});

app.Run();

/// <summary>Login/registration request body.</summary>
internal sealed record Credentials(string Username, string Password);

/// <summary>EF Core Identity store for the demo (in-memory).</summary>
internal sealed class DemoIdentityContext(DbContextOptions<DemoIdentityContext> options)
    : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<IdentityUser>(options);
