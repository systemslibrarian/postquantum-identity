using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
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
TimeSpan TokenLifetime = TimeSpan.FromHours(1);
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

// Asymmetric DoS mitigation. Argon2id and ML-DSA-65 are deliberately expensive
// by design, so an attacker spamming bogus /login or /refresh calls can burn
// disproportionate server CPU. The "auth" policy caps each remote IP to 10
// requests per 30 s on those endpoints. Real deployments should pair this
// with edge-level limits (CDN / API gateway / WAF) — this is the in-process
// last line of defense, not the whole story.
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

// Optional one-shot startup diagnostic: writes a single INFO log line summarising
// the resolved Argon2id configuration so ops can confirm at boot exactly what
// got picked up. Never logs key material, passwords, or token contents.
builder.Services.AddPostQuantumPreflightLogging();

// In-memory revocation list. A real service would back this by Redis / a DB
// table with a TTL matching the token lifetime. The contract here — "is this
// jti revoked?" — is the same regardless of the backing store.
var revokedJtis = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);
builder.Services.AddSingleton(revokedJtis);

// --- Key ring (demonstrates kid-based rotation) ---------------------------
// Two provisioning modes, both ending in the same ring shape:
//
//   Default: two fresh ML-DSA-65 keys per process ("k1" previous, "k2"
//   current) — zero-setup demo convenience.
//
//   Production-shaped: set PQ_ISSUER_KEY_DIR (or Issuer:KeyDirectory) to a
//   directory of <kid>.private.pem files provisioned out of band by the
//   KeyTool sample. The ordinal-highest kid signs — zero-pad date-based names
//   (k-2026-07, not k-2026-7) so the sort order stays chronological.
//   PQ_ISSUER_KEY_PASSWORD decrypts encrypted PKCS#8 files. Hand only the
//   matching *.public.pem files to verifiers (see the Verifier.Demo sample).
//
// New tokens are signed with the current key and stamped with its kid; tokens
// signed by EITHER key still validate, because the verifier resolves the right
// public key by kid.
var signingKeyRing = new Dictionary<string, MLDsa>(StringComparer.Ordinal);
var verifyingKeyRing = new Dictionary<string, MLDsa>(StringComparer.Ordinal);
string currentKeyId = "k2";

string? keyDirectory = builder.Configuration["Issuer:KeyDirectory"]
    ?? Environment.GetEnvironmentVariable("PQ_ISSUER_KEY_DIR");

// Fail closed: explicitly provisioned keys on a host that cannot sign with
// them is a deployment error, not a case for the demo-convenience fallback.
// Without this check the app would boot cleanly, silently ignore the
// operator's keys, and only surface the problem as 503s at first /login.
if (keyDirectory is not null && !MLDsa.IsSupported)
{
    throw new InvalidOperationException(
        "PQ_ISSUER_KEY_DIR / Issuer:KeyDirectory is set, but ML-DSA is unavailable on this host "
        + "(needs Windows CNG or OpenSSL 3.5+ on Linux). Refusing to start while ignoring provisioned keys.");
}

if (MLDsa.IsSupported)
{
    if (keyDirectory is not null)
    {
        LoadSigningKeysFromDirectory(keyDirectory, signingKeyRing);

        // Fail closed: an explicitly configured key directory with no usable
        // keys is a deployment error, not a reason to fall back to random keys.
        currentKeyId = signingKeyRing.Keys.Max(StringComparer.Ordinal)
            ?? throw new InvalidOperationException($"No *.private.pem keys found in {keyDirectory}.");
    }
    else
    {
        foreach (string kid in new[] { "k1", currentKeyId })
        {
            signingKeyRing[kid] = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        }
    }

    foreach ((string kid, MLDsa key) in signingKeyRing)
    {
        verifyingKeyRing[kid] = MLDsa.ImportSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo());
    }

    identity.AddPostQuantumTokens<IdentityUser>(o =>
    {
        o.SigningKey = signingKeyRing[currentKeyId];
        o.KeyId = currentKeyId;            // stamped into the token's `kid` header
        o.Issuer = Issuer;
        o.Audience = Audience;
        o.Lifetime = TokenLifetime;
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
app.UseRateLimiter();

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
    currentKeyId = currentKeyId,
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
}).RequireRateLimiting("auth");

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
        kid = currentKeyId,
        expires_in = (int)TokenLifetime.TotalSeconds,
    });
}).RequireRateLimiting("auth");

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

    // Issue the new token BEFORE revoking the old jti. If issuance throws,
    // the caller still has a working bearer token until natural expiry.
    string newToken = await tokens.CreateTokenAsync(user);

    string? oldJti = ctx.User.FindFirst("jti")?.Value;
    if (oldJti is not null)
    {
        revokedJtis[oldJti] = DateTimeOffset.UtcNow;
    }

    return Results.Ok(new
    {
        token = newToken,
        token_type = "PQ-JWT",
        alg = "ML-DSA-65",
        kid = currentKeyId,
        expires_in = (int)TokenLifetime.TotalSeconds,
        rotated_from = oldJti,
    });
}).RequireRateLimiting("auth");

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
app.MapGet("/me", [Authorize] (HttpContext ctx) =>
{
    string? expRaw = ctx.User.FindFirst("exp")?.Value;
    DateTimeOffset? expiresAt = long.TryParse(expRaw, out long expUnix)
        ? DateTimeOffset.FromUnixTimeSeconds(expUnix)
        : null;

    return Results.Ok(new
    {
        subject = ctx.User.FindFirst("sub")?.Value,
        name = ctx.User.FindFirst("name")?.Value,
        roles = ctx.User.FindAll("role").Select(c => c.Value).ToArray(),
        jti = ctx.User.FindFirst("jti")?.Value,
        expiresAt = expiresAt?.ToString("O"),
    });
});

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

    return Results.Ok(new { keys, current_kid = currentKeyId });
});

app.Run();

// Loads KeyTool-provisioned <kid>.private.pem files into the signing ring, kid
// taken from the file name. The label sniff routes to the right BCL PEM reader
// (native BCL first — no hand-rolled base64/DER handling); anything unexpected
// throws so the host fails at startup instead of signing with a partial ring.
static void LoadSigningKeysFromDirectory(string keyDirectory, Dictionary<string, MLDsa> ring)
{
    string? keyPassword = Environment.GetEnvironmentVariable("PQ_ISSUER_KEY_PASSWORD");
    foreach (string path in Directory.GetFiles(keyDirectory, "*.private.pem"))
    {
        string kid = Path.GetFileName(path)[..^".private.pem".Length];
        string pem = File.ReadAllText(path);
        if (!PemEncoding.TryFind(pem, out PemFields fields))
        {
            throw new InvalidOperationException($"{path} contains no PEM block.");
        }

        ring[kid] = pem[fields.Label] switch
        {
            "PRIVATE KEY" => MLDsa.ImportFromPem(pem),
            "ENCRYPTED PRIVATE KEY" => MLDsa.ImportFromEncryptedPem(
                pem,
                keyPassword ?? throw new InvalidOperationException(
                    $"{path} is encrypted — set PQ_ISSUER_KEY_PASSWORD.")),
            var label => throw new InvalidOperationException(
                $"{path}: unsupported PEM label \"{label}\"."),
        };
    }
}

/// <summary>Login/registration request body.</summary>
internal sealed record Credentials(string Username, string Password);

/// <summary>EF Core Identity store for the demo (in-memory).</summary>
internal sealed class DemoIdentityContext(DbContextOptions<DemoIdentityContext> options)
    : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<IdentityUser>(options);
