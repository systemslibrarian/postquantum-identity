using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;

// ---------------------------------------------------------------------------
// PostQuantum.Identity verifier demo — the OTHER half of the deployment model.
//
// The library's production stance is "adopt the token surface when you own
// both the issuer and every verifier". The issuer half is
// samples/PostQuantum.Identity.Demo; THIS app is a downstream resource
// service in the same fleet:
//
//   ┌─────────────────────┐   PQ-JWT (ML-DSA-65)   ┌──────────────────────┐
//   │ Identity.Demo :5199 │ ──────────────────────>│ Verifier.Demo :5299  │
//   │ issuer              │                        │ resource service     │
//   │ passwords, Argon2id │   public keys only     │ NO passwords         │
//   │ PRIVATE signing keys│ <──── pq-jwks / PEM ───│ NO private keys      │
//   └─────────────────────┘                        │ NO Identity store    │
//                                                  └──────────────────────┘
//
// What this file proves by existing:
//   * A verifier needs only PostQuantum.Jwt.AspNetCore + the issuer's PUBLIC
//     keys. It does not reference PostQuantum.Identity at all.
//   * Public keys arrive one of two ways, both shown here:
//       1. pulled from the issuer's /.well-known/pq-jwks endpoint (default);
//       2. loaded from *.public.pem files provisioned by the KeyTool sample
//          (set Verifier:PublicKeyDirectory or PQ_VERIFIER_KEY_DIR).
//   * Startup is fail-closed: no keys -> the host refuses to start, rather
//     than starting with an endpoint that can never authorize anyone.
//
// Honesty notes:
//   * This verifier checks SIGNATURE + ISSUER + AUDIENCE + EXPIRY. It does NOT
//     see the issuer's revocation list — a token revoked by /logout on the
//     issuer still validates here until it expires. Cross-service revocation
//     needs a shared store (Redis / DB) checked by every verifier; short token
//     lifetimes bound the exposure either way. Stated in KNOWN-GAPS.md too.
//   * The pq-jwks fetch happens once at startup. A production verifier should
//     re-poll (or subscribe) so key rotation propagates without a redeploy —
//     step 2 of the rotation procedure in the README assumes verifiers learn
//     new kids before the issuer signs with them.
// ---------------------------------------------------------------------------

// Must match the issuer's constants — the validator enforces both.
const string Issuer = "https://demo.postquantum-identity.local";
const string Audience = "api://demo";

var builder = WebApplication.CreateBuilder(args);

if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ASPNETCORE_URLS")))
{
    builder.WebHost.UseUrls("http://localhost:5299");
}

if (!MLDsa.IsSupported)
{
    Console.Error.WriteLine(
        "ML-DSA is not available on this host (needs .NET 10 BCL PQC: Windows CNG, or OpenSSL 3.5+ on Linux). "
        + "A verifier that cannot verify must not start — exiting.");
    return 2;
}

// --- Load the issuer's public keys (fail-closed) ---------------------------
string? keyDirectory = builder.Configuration["Verifier:PublicKeyDirectory"]
    ?? Environment.GetEnvironmentVariable("PQ_VERIFIER_KEY_DIR");
string jwksUrl = builder.Configuration["Verifier:JwksUrl"]
    ?? "http://localhost:5199/.well-known/pq-jwks";

Dictionary<string, MLDsa> verifyingKeyRing;
string keySource;
if (keyDirectory is not null)
{
    verifyingKeyRing = LoadPublicKeysFromDirectory(keyDirectory);
    keySource = $"PEM directory {keyDirectory}";
}
else
{
    verifyingKeyRing = await LoadPublicKeysFromJwksAsync(jwksUrl);
    keySource = $"pq-jwks at {jwksUrl}";
}

if (verifyingKeyRing.Count == 0)
{
    Console.Error.WriteLine($"No verification keys could be loaded from {keySource}. "
        + "Refusing to start with an unverifiable [Authorize] surface (fail-closed).");
    return 1;
}

Console.WriteLine($"Loaded {verifyingKeyRing.Count} ML-DSA-65 verification key(s) from {keySource}: "
    + string.Join(", ", verifyingKeyRing.Keys));

// --- Auth pipeline: PqJwtBearer + kid resolution, nothing else --------------
builder.Services
    .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
    .AddPqJwtBearer(o => o.ValidationParameters = new PqJwtValidationParameters
    {
        SignatureKeyResolver = kid =>
            kid is not null && verifyingKeyRing.TryGetValue(kid, out MLDsa? key) ? key : null,
        ValidIssuer = Issuer,
        ValidAudience = Audience,
    });
builder.Services.AddAuthorization();

string[] endpoints = ["GET /", "GET /orders"];

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Ok(new
{
    service = "PostQuantum.Identity verifier demo (resource service)",
    trusts = new { issuer = Issuer, audience = Audience, kids = verifyingKeyRing.Keys },
    keySource,
    endpoints,
}));

// A stand-in for any protected business endpoint. The PqJwtBearer handler has
// already validated the ML-DSA-65 signature (resolving the key by kid), the
// issuer, the audience, and the expiry before this lambda runs — fail-closed,
// so a tampered or foreign token never reaches business logic.
app.MapGet("/orders", [Authorize] (HttpContext ctx) => Results.Ok(new
{
    subject = ctx.User.FindFirst("sub")?.Value,
    name = ctx.User.FindFirst("name")?.Value,
    orders = new[]
    {
        new { id = "ord-1001", item = "quantum-resistant widget", quantity = 2 },
        new { id = "ord-1002", item = "classical fallback sprocket", quantity = 1 },
    },
}));

app.Run();
return 0;

// --- Key-loading helpers ----------------------------------------------------

// Option 1 (default): pull the issuer's published verification keys. Retries
// briefly so "start both apps in either order" works in local walkthroughs.
static async Task<Dictionary<string, MLDsa>> LoadPublicKeysFromJwksAsync(string url)
{
    var ring = new Dictionary<string, MLDsa>(StringComparer.Ordinal);
    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

    const int MaxAttempts = 5;
    for (int attempt = 1; attempt <= MaxAttempts; attempt++)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(await http.GetStringAsync(url));
            foreach (JsonElement key in doc.RootElement.GetProperty("keys").EnumerateArray())
            {
                string? kid = key.GetProperty("kid").GetString();
                string? spkiB64 = key.GetProperty("spki_b64").GetString();
                if (kid is not null && spkiB64 is not null)
                {
                    ring[kid] = MLDsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(spkiB64));
                }
            }

            return ring;
        }
        // FormatException / CryptographicException cover a malformed spki_b64
        // or a non-ML-DSA key in the document: those must land on this same
        // fail-closed path (retry, then refuse to start) — not escape as an
        // unhandled crash halfway through loading the ring.
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException
            or KeyNotFoundException or FormatException or CryptographicException)
        {
            Console.WriteLine($"pq-jwks fetch attempt {attempt}/{MaxAttempts} failed ({ex.GetType().Name}); "
                + (attempt < MaxAttempts ? "retrying in 2 s — is the issuer demo running on :5199?" : "giving up."));
            if (attempt < MaxAttempts)
            {
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
        }
    }

    return ring;
}

// Option 2: file-based provisioning — *.public.pem files created by the
// KeyTool sample, with the kid taken from the file name (k-2026-07.public.pem
// -> kid "k-2026-07"). This is the pattern for fleets where verifiers must not
// depend on the issuer being reachable at boot.
static Dictionary<string, MLDsa> LoadPublicKeysFromDirectory(string directory)
{
    var ring = new Dictionary<string, MLDsa>(StringComparer.Ordinal);
    foreach (string path in Directory.GetFiles(directory, "*.public.pem"))
    {
        string pem = File.ReadAllText(path);
        // The label check is load-bearing: a stray private key in the verifier's
        // directory must be refused loudly, not imported. The import itself uses
        // the BCL PEM reader (native BCL first — no hand-rolled base64/DER).
        if (!PemEncoding.TryFind(pem, out PemFields fields) || pem[fields.Label] != "PUBLIC KEY")
        {
            Console.Error.WriteLine($"Skipping {path}: not a PUBLIC KEY PEM.");
            continue;
        }

        string kid = Path.GetFileName(path)[..^".public.pem".Length];
        ring[kid] = MLDsa.ImportFromPem(pem);
    }

    return ring;
}
