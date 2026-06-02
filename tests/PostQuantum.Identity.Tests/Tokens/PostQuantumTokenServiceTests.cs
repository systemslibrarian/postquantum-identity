#if NET10_0_OR_GREATER
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using PostQuantum.Identity.Tokens;
using PostQuantum.Jwt;
using Xunit;

namespace PostQuantum.Identity.Tests.Tokens;

/// <summary>
/// End-to-end tests for the hybrid-token service: issue a token for an Identity
/// user, then validate it with the genuine <see cref="PqJwtValidator"/>.
/// </summary>
/// <remarks>
/// These touch the native BCL ML-DSA primitive. Where it is unavailable (older
/// OpenSSL on Linux), the facts skip themselves with a reason rather than fail.
/// </remarks>
public class PostQuantumTokenServiceTests
{
    private static bool MLDsaSupported => MLDsa.IsSupported;
    private const string SkipReason = "ML-DSA-65 unavailable on this host (needs OpenSSL 3.5+ or a recent Windows).";

    private static UserManager<FakeUser> NewUserManager()
    {
        // The token service only reads from the store; the rest of UserManager's
        // dependencies are not exercised, so nulls/defaults are sufficient.
        return new UserManager<FakeUser>(
            new FakeUserStore(),
            optionsAccessor: null!,
            passwordHasher: null!,
            userValidators: [],
            passwordValidators: [],
            keyNormalizer: null!,
            errors: new IdentityErrorDescriber(),
            services: null!,
            logger: null!);
    }

    private static PostQuantumTokenService<FakeUser> NewService(MLDsa signingKey, FakeUser user, out FakeUser captured)
    {
        captured = user;
        var options = Options.Create(new PostQuantumTokenOptions
        {
            SigningKey = signingKey,
            Issuer = "https://issuer.test",
            Audience = "api://resource",
            Lifetime = TimeSpan.FromMinutes(15),
        });
        return new PostQuantumTokenService<FakeUser>(NewUserManager(), options);
    }

    [SkippableFact]
    public async Task Issued_token_validates_and_carries_identity_claims()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var user = new FakeUser { UserName = "ada", Email = "ada@example.com" };
        user.Roles.Add("admin");
        user.Claims.Add(new Claim("department", "research"));

        PostQuantumTokenService<FakeUser> service = NewService(signingKey, user, out _);
        string token = await service.CreateTokenAsync(user);

        // Validate with the real validator using the matching public key.
        using MLDsa verifyKey = MLDsa.ImportSubjectPublicKeyInfo(signingKey.ExportSubjectPublicKeyInfo());
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verifyKey,
            ValidIssuer = "https://issuer.test",
            ValidAudience = "api://resource",
        });

        PqJwtValidationResult result = validator.Validate(token);

        Assert.Equal(user.Id, result.Subject);
        Assert.Equal("https://issuer.test", result.Issuer);
        Assert.Equal("ada", result.GetString("name"));
        Assert.Equal("ada@example.com", result.GetString("email"));
        Assert.Equal("admin", result.GetString("role"));
        Assert.Equal("research", result.GetString("department"));
        Assert.False(result.WasEncrypted);
    }

    [SkippableFact]
    public async Task Token_validation_fails_for_wrong_audience()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var user = new FakeUser();
        PostQuantumTokenService<FakeUser> service = NewService(signingKey, user, out _);
        string token = await service.CreateTokenAsync(user);

        using MLDsa verifyKey = MLDsa.ImportSubjectPublicKeyInfo(signingKey.ExportSubjectPublicKeyInfo());
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verifyKey,
            ValidIssuer = "https://issuer.test",
            ValidAudience = "api://WRONG",
        });

        Assert.ThrowsAny<PqJwtException>(() => validator.Validate(token));
    }

    [SkippableFact]
    public async Task Issued_token_carries_the_configured_kid_header()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        using MLDsa signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var options = Options.Create(new PostQuantumTokenOptions
        {
            SigningKey = signingKey,
            KeyId = "k-2026-06",
            Issuer = "https://issuer.test",
            Audience = "api://resource",
        });
        var service = new PostQuantumTokenService<FakeUser>(NewUserManager(), options);

        string token = await service.CreateTokenAsync(new FakeUser());

        // Decode the JWS protected header (first compact segment).
        string headerJson = DecodeSegment(token.Split('.')[0]);
        Assert.Contains("\"kid\":\"k-2026-06\"", headerJson, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task Token_from_rotated_key_validates_via_kid_resolver()
    {
        Skip.IfNot(MLDsaSupported, SkipReason);

        // A two-key ring: tokens signed with the *current* key must validate when
        // the verifier resolves keys by kid — the rotation contract.
        using MLDsa previous = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using MLDsa current = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var ring = new Dictionary<string, MLDsa>(StringComparer.Ordinal)
        {
            ["k1"] = MLDsa.ImportSubjectPublicKeyInfo(previous.ExportSubjectPublicKeyInfo()),
            ["k2"] = MLDsa.ImportSubjectPublicKeyInfo(current.ExportSubjectPublicKeyInfo()),
        };

        var options = Options.Create(new PostQuantumTokenOptions
        {
            SigningKey = current,
            KeyId = "k2",
            Issuer = "https://issuer.test",
            Audience = "api://resource",
        });
        var service = new PostQuantumTokenService<FakeUser>(NewUserManager(), options);
        string token = await service.CreateTokenAsync(new FakeUser());

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureKeyResolver = kid => kid is not null && ring.TryGetValue(kid, out MLDsa? k) ? k : null,
            ValidIssuer = "https://issuer.test",
            ValidAudience = "api://resource",
        });

        PqJwtValidationResult result = validator.Validate(token);
        Assert.NotNull(result.Subject);

        foreach (MLDsa k in ring.Values)
        {
            k.Dispose();
        }
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

    [Fact]
    public void Options_validation_requires_a_signing_key()
    {
        var options = Options.Create(new PostQuantumTokenOptions
        {
            Issuer = "i",
            Audience = "a",
        });
        Assert.Throws<InvalidOperationException>(
            () => new PostQuantumTokenService<FakeUser>(NewUserManager(), options));
    }
}
#endif
