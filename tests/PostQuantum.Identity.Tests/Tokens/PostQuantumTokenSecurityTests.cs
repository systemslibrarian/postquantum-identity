#if NET10_0_OR_GREATER
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using PostQuantum.Identity.Tokens;
using PostQuantum.Jwt;
using PostQuantum.Jwt.Cryptography;
using Xunit;

namespace PostQuantum.Identity.Tests.Tokens;

/// <summary>
/// Security-focused tests for issued tokens: encryption roundtrip, multi-role
/// claims, lifetime enforcement, and a fail-closed tamper/negative corpus. These
/// are the "validation test vectors" for the token surface.
/// </summary>
public class PostQuantumTokenSecurityTests
{
    private static bool MLDsaSupported => MLDsa.IsSupported;
    private const string SkipReason = "ML-DSA-65 unavailable on this host (needs OpenSSL 3.5+ or a recent Windows).";
    private const string Iss = "https://issuer.test";
    private const string Aud = "api://resource";

    /// <summary>A fixed clock so token lifetimes are deterministic in tests.</summary>
    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static UserManager<FakeUser> NewUserManager() => new(
        new FakeUserStore(), null!, null!, [], [], null!, new IdentityErrorDescriber(), null!, null!);

    private static PostQuantumTokenService<FakeUser> NewService(
        MLDsa key, FakeUser user, out UserManager<FakeUser> users,
        XWingPublicKey? encryptFor = null, TimeProvider? clock = null)
    {
        users = NewUserManager();
        var options = Options.Create(new PostQuantumTokenOptions
        {
            SigningKey = key,
            Issuer = Iss,
            Audience = Aud,
            Lifetime = TimeSpan.FromMinutes(15),
            EncryptForRecipient = encryptFor,
        });
        return new PostQuantumTokenService<FakeUser>(users, options, clock);
    }

    private static PqJwtValidator Validator(MLDsa verifyKey, XWingPrivateKey? decryptionKey = null, TimeProvider? clock = null) =>
        new(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verifyKey,
            ValidIssuer = Iss,
            ValidAudience = Aud,
            DecryptionKey = decryptionKey,
        }, clock);

    private static MLDsa PublicOf(MLDsa key) => MLDsa.ImportSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo());

    [SkippableFact]
    public async Task Sign_then_encrypt_roundtrips_and_marks_encrypted()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using XWingPrivateKey recipient = XWingPrivateKey.Generate();

        var user = new FakeUser { UserName = "ada" };
        PostQuantumTokenService<FakeUser> service = NewService(key, user, out _, encryptFor: recipient.PublicKey);
        string token = await service.CreateTokenAsync(user);

        // A signed-then-encrypted token is 5 compact segments.
        Assert.Equal(5, token.Split('.').Length);

        using MLDsa verify = PublicOf(key);
        PqJwtValidationResult result = Validator(verify, decryptionKey: recipient).Validate(token);

        Assert.True(result.WasEncrypted);
        Assert.Equal(user.Id, result.Subject);
        Assert.Equal("ada", result.GetString("name"));
    }

    [SkippableFact]
    public async Task Multiple_roles_serialize_as_a_json_array()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var user = new FakeUser();
        user.Roles.Add("admin");
        user.Roles.Add("auditor");

        PostQuantumTokenService<FakeUser> service = NewService(key, user, out _);
        string token = await service.CreateTokenAsync(user);

        using MLDsa verify = PublicOf(key);
        PqJwtValidationResult result = Validator(verify).Validate(token);

        System.Text.Json.JsonElement roles = result.Claims["role"];
        Assert.Equal(System.Text.Json.JsonValueKind.Array, roles.ValueKind);
        string[] values = [.. roles.EnumerateArray().Select(e => e.GetString()!)];
        Assert.Equal(["admin", "auditor"], values);
    }

    [SkippableFact]
    public async Task Custom_user_claims_flow_through_but_cannot_override_reserved()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var user = new FakeUser();
        user.Claims.Add(new Claim("department", "research"));
        user.Claims.Add(new Claim("sub", "attacker-controlled")); // reserved — must be ignored

        PostQuantumTokenService<FakeUser> service = NewService(key, user, out _);
        string token = await service.CreateTokenAsync(user);

        using MLDsa verify = PublicOf(key);
        PqJwtValidationResult result = Validator(verify).Validate(token);

        Assert.Equal("research", result.GetString("department"));
        Assert.Equal(user.Id, result.Subject); // not "attacker-controlled"
    }

    [SkippableFact]
    public async Task Expired_token_is_rejected()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var user = new FakeUser();

        // Issue with a clock in the past so exp is already behind the real-time validator.
        var pastClock = new FixedClock(new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero));
        PostQuantumTokenService<FakeUser> service = NewService(key, user, out _, clock: pastClock);
        string token = await service.CreateTokenAsync(user);

        using MLDsa verify = PublicOf(key);
        Assert.ThrowsAny<PqJwtException>(() => Validator(verify).Validate(token));
    }

    [SkippableFact]
    public async Task Wrong_signing_key_is_rejected()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using MLDsa attacker = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var user = new FakeUser();
        PostQuantumTokenService<FakeUser> service = NewService(key, user, out _);
        string token = await service.CreateTokenAsync(user);

        using MLDsa wrong = PublicOf(attacker);
        Assert.ThrowsAny<PqJwtException>(() => Validator(wrong).Validate(token));
    }

    [SkippableTheory]
    [InlineData(0)] // header
    [InlineData(1)] // payload
    [InlineData(2)] // signature
    public async Task Tampering_any_segment_is_rejected(int segmentIndex)
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var user = new FakeUser();
        PostQuantumTokenService<FakeUser> service = NewService(key, user, out _);
        string token = await service.CreateTokenAsync(user);

        string[] parts = token.Split('.');
        parts[segmentIndex] = FlipLastChar(parts[segmentIndex]);
        string tampered = string.Join('.', parts);

        using MLDsa verify = PublicOf(key);
        Assert.ThrowsAny<PqJwtException>(() => Validator(verify).Validate(tampered));
    }

    [SkippableTheory]
    [InlineData("")]
    [InlineData("not-a-token")]
    [InlineData("only.two")]
    [InlineData("a.b.c.d")] // 4 segments: neither a valid JWS nor JWE
    public void Malformed_tokens_are_rejected(string token)
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using MLDsa verify = PublicOf(key);

        // Fail-closed: malformed input is rejected — either by the validator's
        // input guard (ArgumentException, e.g. empty string) or by structural
        // validation (PqJwtException). It must never return a result.
        Exception ex = Record.Exception(() => Validator(verify).Validate(token));
        Assert.True(ex is PqJwtException or ArgumentException, $"Unexpected exception type: {ex?.GetType().Name ?? "<none>"}");
    }

    private static string FlipLastChar(string segment)
    {
        char last = segment[^1];
        char replacement = last == 'A' ? 'B' : 'A';
        return segment[..^1] + replacement;
    }
}
#endif
