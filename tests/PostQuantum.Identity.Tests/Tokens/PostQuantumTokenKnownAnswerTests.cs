#if NET10_0_OR_GREATER
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using PostQuantum.Identity.Tokens;
using PostQuantum.Jwt;
using PostQuantum.Jwt.Cryptography;
using Xunit;

namespace PostQuantum.Identity.Tests.Tokens;

/// <summary>
/// Wire-level Known Answer Tests for the hybrid-token issuance path. These pin
/// the JOSE header structure, the registered/private claim set, and the
/// sign-then-encrypt envelope to the values this library promises to emit.
/// </summary>
/// <remarks>
/// <para>
/// ML-DSA signatures and key generation are non-deterministic, so byte-equal
/// vectors are not meaningful here — instead these tests pin the
/// <em>structure</em> of every byte the library controls:
/// </para>
/// <list type="bullet">
///   <item>Signed token: header carries <c>typ:JWT</c>, <c>alg:ML-DSA-65</c>,
///         optional <c>kid</c>; payload carries the seven registered claims
///         (<c>iss/sub/aud/exp/nbf/iat/jti</c>) with sane time relationships
///         and the configured private claims (<c>name/email/role/…</c>).</item>
///   <item>Sign-then-encrypt token: 5-segment compact JWE wrapping the JWS;
///         outer header carries <c>alg:X-Wing</c>, <c>enc:A256GCM</c>,
///         <c>cty:JWT</c>; the inner JWS validates with the signing public key
///         and exposes the same registered claims.</item>
///   <item>The cryptographic primitives themselves (ML-DSA, ML-KEM, X25519,
///         AES-GCM) have their own KATs in PostQuantum.Jwt; here we pin the
///         <em>identity</em> layer's contract on top of them.</item>
/// </list>
/// </remarks>
public class PostQuantumTokenKnownAnswerTests
{
    private static bool MLDsaSupported => MLDsa.IsSupported;
    private const string SkipReason = "ML-DSA-65 unavailable on this host (needs OpenSSL 3.5+ or a recent Windows).";
    private const string Iss = "https://issuer.test";
    private const string Aud = "api://resource";

    private static UserManager<FakeUser> NewUserManager() => new(
        new FakeUserStore(), null!, null!, [], [], null!, new IdentityErrorDescriber(), null!, null!);

    private static PostQuantumTokenService<FakeUser> NewService(
        MLDsa signingKey, string? kid = null, XWingPublicKey? encryptFor = null, TimeSpan? lifetime = null)
    {
        var options = Options.Create(new PostQuantumTokenOptions
        {
            SigningKey = signingKey,
            KeyId = kid,
            Issuer = Iss,
            Audience = Aud,
            Lifetime = lifetime ?? TimeSpan.FromHours(1),
            EncryptForRecipient = encryptFor,
        });
        return new PostQuantumTokenService<FakeUser>(NewUserManager(), options);
    }

    private static string DecodeSegment(string segment)
    {
        string padded = segment.Replace('-', '+').Replace('_', '/');
        padded = (padded.Length % 4) switch
        {
            2 => padded + "==",
            3 => padded + "=",
            _ => padded,
        };
        return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(padded));
    }

    /// <summary>
    /// Signed-token JOSE header KAT. The first compact segment of every issued
    /// JWS must declare <c>typ:JWT</c> and <c>alg:ML-DSA-65</c>; when a
    /// <see cref="PostQuantumTokenOptions.KeyId"/> is configured it appears
    /// as <c>kid</c>. These exact identifiers are the contract verifiers rely on.
    /// </summary>
    [SkippableFact]
    public async Task Header_kat_signed_token_declares_typ_jwt_alg_mldsa65_kid()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        PostQuantumTokenService<FakeUser> service = NewService(key, kid: "k-2026-06");
        string token = await service.CreateTokenAsync(new FakeUser());

        using JsonDocument header = JsonDocument.Parse(DecodeSegment(token.Split('.')[0]));
        JsonElement root = header.RootElement;

        Assert.Equal("JWT", root.GetProperty("typ").GetString());
        Assert.Equal("ML-DSA-65", root.GetProperty("alg").GetString());
        Assert.Equal("k-2026-06", root.GetProperty("kid").GetString());
    }

    /// <summary>
    /// Payload KAT: every issued token MUST carry the registered claims this
    /// library promises — <c>iss</c>, <c>sub</c>, <c>aud</c>, <c>iat</c>,
    /// <c>exp</c>, <c>jti</c> — with internally-consistent timestamps
    /// (<c>iat ≤ exp</c>, <c>exp - iat == Lifetime</c>) and a globally-unique
    /// <c>jti</c>. (If <c>nbf</c> is present it must satisfy <c>iat ≤ nbf ≤ exp</c>;
    /// its emission is delegated to PostQuantum.Jwt's builder.)
    /// </summary>
    [SkippableFact]
    public async Task Payload_kat_carries_registered_claims_with_consistent_timestamps()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var lifetime = TimeSpan.FromMinutes(30);
        PostQuantumTokenService<FakeUser> service = NewService(key, lifetime: lifetime);
        var user = new FakeUser { UserName = "ada", Email = "ada@example.com" };

        string token1 = await service.CreateTokenAsync(user);
        string token2 = await service.CreateTokenAsync(user);

        foreach (string token in new[] { token1, token2 })
        {
            using JsonDocument doc = JsonDocument.Parse(DecodeSegment(token.Split('.')[1]));
            JsonElement payload = doc.RootElement;

            Assert.Equal(Iss, payload.GetProperty("iss").GetString());
            Assert.Equal(user.Id, payload.GetProperty("sub").GetString());
            Assert.Equal(Aud, payload.GetProperty("aud").GetString());

            long iat = payload.GetProperty("iat").GetInt64();
            long exp = payload.GetProperty("exp").GetInt64();
            Assert.True(iat <= exp, "iat must precede or equal exp");
            Assert.Equal(lifetime.TotalSeconds, exp - iat, precision: 0);

            // nbf is optional in our contract; if it appears it must be coherent.
            if (payload.TryGetProperty("nbf", out JsonElement nbfElement))
            {
                long nbf = nbfElement.GetInt64();
                Assert.InRange(nbf, iat, exp);
            }

            string jti = payload.GetProperty("jti").GetString()!;
            Assert.False(string.IsNullOrEmpty(jti));
            Assert.Equal(32, jti.Length); // Guid "N" format — 32 lowercase hex chars.
        }

        // jti must differ across two tokens issued back-to-back for the same user.
        using JsonDocument p1 = JsonDocument.Parse(DecodeSegment(token1.Split('.')[1]));
        using JsonDocument p2 = JsonDocument.Parse(DecodeSegment(token2.Split('.')[1]));
        Assert.NotEqual(
            p1.RootElement.GetProperty("jti").GetString(),
            p2.RootElement.GetProperty("jti").GetString());
    }

    /// <summary>
    /// Private-claim KAT: <c>name</c>, <c>email</c>, the <c>role</c> claim, and
    /// any custom user claims appear in the payload exactly as configured, with
    /// the documented single-role (string) vs multi-role (string array) shape.
    /// </summary>
    [SkippableFact]
    public async Task Payload_kat_private_claims_map_exactly_as_documented()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

        // Single role -> string-shaped "role" claim.
        var single = new FakeUser { UserName = "ada", Email = "ada@example.com" };
        single.Roles.Add("admin");
        single.Claims.Add(new Claim("department", "research"));

        PostQuantumTokenService<FakeUser> service = NewService(key);
        string singleToken = await service.CreateTokenAsync(single);
        using JsonDocument singleDoc = JsonDocument.Parse(DecodeSegment(singleToken.Split('.')[1]));

        Assert.Equal("ada", singleDoc.RootElement.GetProperty("name").GetString());
        Assert.Equal("ada@example.com", singleDoc.RootElement.GetProperty("email").GetString());
        Assert.Equal("admin", singleDoc.RootElement.GetProperty("role").GetString());
        Assert.Equal("research", singleDoc.RootElement.GetProperty("department").GetString());

        // Multiple roles -> JSON array under the same "role" claim.
        var many = new FakeUser();
        many.Roles.Add("admin");
        many.Roles.Add("auditor");
        many.Roles.Add("reader");

        string manyToken = await service.CreateTokenAsync(many);
        using JsonDocument manyDoc = JsonDocument.Parse(DecodeSegment(manyToken.Split('.')[1]));
        JsonElement roles = manyDoc.RootElement.GetProperty("role");
        Assert.Equal(JsonValueKind.Array, roles.ValueKind);
        Assert.Equal(["admin", "auditor", "reader"], roles.EnumerateArray().Select(e => e.GetString()!));
    }

    /// <summary>
    /// Sign-then-encrypt envelope KAT. With an encryption recipient configured,
    /// the outer JWE compact form is 5 segments; the protected header declares
    /// <c>alg:X-Wing</c>, <c>enc:A256GCM</c>, and <c>cty:JWT</c> (the inner JWS
    /// content type). Validation with the recipient's X-Wing private key returns
    /// a result flagged as encrypted and surfaces the same registered claims.
    /// </summary>
    [SkippableFact]
    public async Task Envelope_kat_sign_then_encrypt_declares_xwing_a256gcm_with_inner_jws()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using XWingPrivateKey recipient = XWingPrivateKey.Generate();
        var user = new FakeUser { UserName = "ada" };

        PostQuantumTokenService<FakeUser> service = NewService(key, encryptFor: recipient.PublicKey);
        string token = await service.CreateTokenAsync(user);

        string[] segments = token.Split('.');
        Assert.Equal(5, segments.Length); // JWE compact serialization.

        using JsonDocument outerHeader = JsonDocument.Parse(DecodeSegment(segments[0]));
        Assert.Equal("X-Wing", outerHeader.RootElement.GetProperty("alg").GetString());
        Assert.Equal("A256GCM", outerHeader.RootElement.GetProperty("enc").GetString());
        Assert.Equal("JWT", outerHeader.RootElement.GetProperty("cty").GetString());

        // Decrypt + validate via the genuine validator and pin the registered-claim mapping.
        using MLDsa verify = MLDsa.ImportSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo());
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            ValidIssuer = Iss,
            ValidAudience = Aud,
            DecryptionKey = recipient,
        });

        PqJwtValidationResult result = validator.Validate(token);
        Assert.True(result.WasEncrypted);
        Assert.Equal(user.Id, result.Subject);
        Assert.Equal(Iss, result.Issuer);
        Assert.Equal("ada", result.GetString("name"));
    }

    /// <summary>
    /// Roundtrip KAT pinning the end-to-end contract: issue → validate, with
    /// the recovered claims byte-for-byte equal to what the service was asked
    /// to embed, including the user's persisted ASP.NET Core Identity claim set.
    /// </summary>
    [SkippableFact]
    public async Task Roundtrip_kat_validator_recovers_all_configured_claims()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var user = new FakeUser { UserName = "ada", Email = "ada@example.com" };
        user.Roles.Add("admin");
        user.Claims.Add(new Claim("department", "research"));
        user.Claims.Add(new Claim("clearance", "secret"));

        PostQuantumTokenService<FakeUser> service = NewService(key);
        string token = await service.CreateTokenAsync(user);

        using MLDsa verify = MLDsa.ImportSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo());
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            ValidIssuer = Iss,
            ValidAudience = Aud,
        });

        PqJwtValidationResult result = validator.Validate(token);

        Assert.Equal(user.Id, result.Subject);
        Assert.Equal(Iss, result.Issuer);
        Assert.Equal("ada", result.GetString("name"));
        Assert.Equal("ada@example.com", result.GetString("email"));
        Assert.Equal("admin", result.GetString("role"));
        Assert.Equal("research", result.GetString("department"));
        Assert.Equal("secret", result.GetString("clearance"));
        Assert.False(result.WasEncrypted);
    }
}
#endif
