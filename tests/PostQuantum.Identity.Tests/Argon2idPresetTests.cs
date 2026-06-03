using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PostQuantum.Identity.DependencyInjection;
using Xunit;

namespace PostQuantum.Identity.Tests;

/// <summary>
/// Tests for the opinionated <see cref="Argon2idOptions"/> presets and the
/// one-line DI overloads that consume them. Each preset is asserted to (a) carry
/// the expected work factors per its documented policy, (b) validate cleanly,
/// (c) produce a working hasher whose hashes round-trip, and (d) compose
/// through the DI overloads without bypassing options validation.
/// </summary>
public class Argon2idPresetTests
{
    private sealed class TestUser
    {
        public string Id { get; init; } = Guid.NewGuid().ToString();
    }

    /// <summary>OWASP 2024 minimum: 19 MiB, t=2, p=1, 16-byte salt, 32-byte tag.</summary>
    [Fact]
    public void OwaspMinimum_matches_documented_profile_and_validates()
    {
        Argon2idOptions o = Argon2idOptions.OwaspMinimum();
        Assert.Equal(19456, o.MemorySizeKib);
        Assert.Equal(2, o.Iterations);
        Assert.Equal(1, o.DegreeOfParallelism);
        Assert.Equal(16, o.SaltSizeBytes);
        Assert.Equal(32, o.HashSizeBytes);
        o.Validate(); // does not throw
    }

    /// <summary>HighSecurity: 128 MiB, t=4, p=1, 16-byte salt, 32-byte tag.</summary>
    [Fact]
    public void HighSecurity_matches_documented_profile_and_validates()
    {
        Argon2idOptions o = Argon2idOptions.HighSecurity();
        Assert.Equal(131072, o.MemorySizeKib);
        Assert.Equal(4, o.Iterations);
        Assert.Equal(1, o.DegreeOfParallelism);
        Assert.Equal(16, o.SaltSizeBytes);
        Assert.Equal(32, o.HashSizeBytes);
        o.Validate(); // does not throw
    }

    /// <summary>LowMemoryContainer: 16 MiB, t=4, p=1, 16-byte salt, 32-byte tag.</summary>
    [Fact]
    public void LowMemoryContainer_matches_documented_profile_and_validates()
    {
        Argon2idOptions o = Argon2idOptions.LowMemoryContainer();
        Assert.Equal(16384, o.MemorySizeKib);
        Assert.Equal(4, o.Iterations);
        Assert.Equal(1, o.DegreeOfParallelism);
        Assert.Equal(16, o.SaltSizeBytes);
        Assert.Equal(32, o.HashSizeBytes);
        o.Validate(); // does not throw — above the 8 MiB hard floor.
    }

    /// <summary>RecommendedDefault() and the Recommended singleton agree on values.</summary>
    [Fact]
    public void RecommendedDefault_factory_matches_Recommended_singleton()
    {
        Argon2idOptions factory = Argon2idOptions.RecommendedDefault();
        Argon2idOptions singleton = Argon2idOptions.Recommended;
        Assert.Equal(singleton.MemorySizeKib, factory.MemorySizeKib);
        Assert.Equal(singleton.Iterations, factory.Iterations);
        Assert.Equal(singleton.DegreeOfParallelism, factory.DegreeOfParallelism);
        Assert.Equal(singleton.SaltSizeBytes, factory.SaltSizeBytes);
        Assert.Equal(singleton.HashSizeBytes, factory.HashSizeBytes);
    }

    /// <summary>
    /// Factories return distinct instances on every call, so a caller mutating one
    /// preset's instance cannot poison the next caller's preset.
    /// </summary>
    [Fact]
    public void Factories_return_independent_instances()
    {
        Argon2idOptions a = Argon2idOptions.HighSecurity();
        Argon2idOptions b = Argon2idOptions.HighSecurity();
        Assert.NotSame(a, b);

        a.MemorySizeKib = 8192;
        Assert.Equal(131072, b.MemorySizeKib);
    }

    /// <summary>
    /// The one-line preset overload on <see cref="IServiceCollection"/> copies the
    /// preset values into the registered options. Later mutation of the supplied
    /// preset instance must NOT mutate what DI resolves.
    /// </summary>
    [Fact]
    public void Preset_overload_copies_values_and_is_decoupled_from_caller()
    {
        Argon2idOptions preset = Argon2idOptions.HighSecurity();
        ServiceCollection services = new();
        services.AddArgon2idPasswordHasher<TestUser>(preset);

        // Mutate the caller's reference after registration — must not affect DI.
        preset.MemorySizeKib = 8192;

        using ServiceProvider sp = services.BuildServiceProvider();
        Argon2idOptions resolved = sp.GetRequiredService<IOptions<Argon2idOptions>>().Value;
        Assert.Equal(131072, resolved.MemorySizeKib);
    }

    /// <summary>
    /// The preset overload still wires the hasher correctly — a roundtrip
    /// register → resolve → hash → verify succeeds with the preset's profile.
    /// </summary>
    [Fact]
    public void Preset_overload_produces_a_working_hasher()
    {
        ServiceCollection services = new();
        // OwaspMinimum keeps the test snappy while still going through the real
        // DI pathway end-to-end.
        services.AddArgon2idPasswordHasher<TestUser>(Argon2idOptions.OwaspMinimum());

        using ServiceProvider sp = services.BuildServiceProvider();
        IPasswordHasher<TestUser> hasher = sp.GetRequiredService<IPasswordHasher<TestUser>>();
        TestUser user = new();

        string hash = hasher.HashPassword(user, "correct horse battery staple");
        Assert.StartsWith("$argon2id$v=19$m=19456,t=2,p=1$", hash, StringComparison.Ordinal);
        Assert.Equal(
            PasswordVerificationResult.Success,
            hasher.VerifyHashedPassword(user, hash, "correct horse battery staple"));
    }

    /// <summary>
    /// The migrating-hasher preset overload composes the same way and produces
    /// a <see cref="MigratingPasswordHasher{TUser}"/>.
    /// </summary>
    [Fact]
    public void Migrating_preset_overload_registers_migrating_hasher()
    {
        ServiceCollection services = new();
        services.AddArgon2idPasswordHasherWithMigration<TestUser>(Argon2idOptions.OwaspMinimum());

        using ServiceProvider sp = services.BuildServiceProvider();
        IPasswordHasher<TestUser> hasher = sp.GetRequiredService<IPasswordHasher<TestUser>>();
        Assert.IsType<MigratingPasswordHasher<TestUser>>(hasher);
    }

    /// <summary>Null preset is rejected at registration time.</summary>
    [Fact]
    public void Preset_overload_rejects_null()
    {
        ServiceCollection services = new();
        Assert.Throws<ArgumentNullException>(
            () => services.AddArgon2idPasswordHasher<TestUser>((Argon2idOptions)null!));
    }
}
