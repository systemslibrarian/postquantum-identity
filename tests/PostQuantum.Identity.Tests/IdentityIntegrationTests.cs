using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using PostQuantum.Identity.DependencyInjection;
using Xunit;

namespace PostQuantum.Identity.Tests;

public class IdentityIntegrationTests
{
    private sealed class TestUser
    {
        public string Id { get; init; } = Guid.NewGuid().ToString();
    }

    private static Argon2idPasswordHasher<TestUser> NewAdapter() =>
        new(new Argon2idPasswordHasher(TestDefaults.FastOptions()));

    [Fact]
    public void Adapter_maps_success()
    {
        var adapter = NewAdapter();
        var user = new TestUser();
        string hash = adapter.HashPassword(user, "pw");
        Assert.Equal(PasswordVerificationResult.Success, adapter.VerifyHashedPassword(user, hash, "pw"));
    }

    [Fact]
    public void Adapter_maps_failure()
    {
        var adapter = NewAdapter();
        var user = new TestUser();
        string hash = adapter.HashPassword(user, "pw");
        Assert.Equal(PasswordVerificationResult.Failed, adapter.VerifyHashedPassword(user, hash, "nope"));
    }

    [Fact]
    public void Adapter_maps_rehash_needed()
    {
        var user = new TestUser();
        string weak = new Argon2idPasswordHasher<TestUser>(
                new Argon2idPasswordHasher(new Argon2idOptions { MemorySizeKib = 8192, Iterations = 1 }))
            .HashPassword(user, "pw");

        var strong = new Argon2idPasswordHasher<TestUser>(
            new Argon2idPasswordHasher(new Argon2idOptions { MemorySizeKib = 16384, Iterations = 2 }));

        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            strong.VerifyHashedPassword(user, weak, "pw"));
    }

    [Fact]
    public void IsArgon2idHash_recognizes_only_argon2id_phc()
    {
        string argon = new Argon2idPasswordHasher(TestDefaults.FastOptions()).HashPassword("pw");
        Assert.True(Argon2idPasswordHasher.IsArgon2idHash(argon));
        Assert.False(Argon2idPasswordHasher.IsArgon2idHash(null));
        Assert.False(Argon2idPasswordHasher.IsArgon2idHash(""));
        Assert.False(Argon2idPasswordHasher.IsArgon2idHash("AQAAAAIAAYagAAAA...")); // PBKDF2-ish
        Assert.False(Argon2idPasswordHasher.IsArgon2idHash("$argon2i$v=19$..."));   // different variant
    }

    [Fact]
    public void Migrating_hasher_verifies_legacy_pbkdf2_and_requests_rehash()
    {
        var user = new TestUser();
        var argon2id = new Argon2idPasswordHasher<TestUser>(new Argon2idPasswordHasher(TestDefaults.FastOptions()));
        var legacy = new PasswordHasher<TestUser>(); // stock PBKDF2
        var migrating = new MigratingPasswordHasher<TestUser>(argon2id, legacy);

        // A password stored under the legacy hasher...
        string legacyHash = legacy.HashPassword(user, "pw");

        // ...verifies through the migrating hasher AND asks for a rehash to Argon2id.
        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            migrating.VerifyHashedPassword(user, legacyHash, "pw"));

        // New hashes come out as Argon2id and verify cleanly (no rehash).
        string upgraded = migrating.HashPassword(user, "pw");
        Assert.True(Argon2idPasswordHasher.IsArgon2idHash(upgraded));
        Assert.Equal(PasswordVerificationResult.Success, migrating.VerifyHashedPassword(user, upgraded, "pw"));
    }

    [Fact]
    public void Migrating_hasher_fails_closed_on_garbage_and_wrong_password()
    {
        var user = new TestUser();
        var migrating = new MigratingPasswordHasher<TestUser>(
            new Argon2idPasswordHasher<TestUser>(new Argon2idPasswordHasher(TestDefaults.FastOptions())),
            new PasswordHasher<TestUser>());

        Assert.Equal(PasswordVerificationResult.Failed, migrating.VerifyHashedPassword(user, "not-base64-garbage", "pw"));

        string legacyHash = new PasswordHasher<TestUser>().HashPassword(user, "pw");
        Assert.Equal(PasswordVerificationResult.Failed, migrating.VerifyHashedPassword(user, legacyHash, "wrong"));
    }

    [Fact]
    public void DI_registers_migrating_hasher()
    {
        var services = new ServiceCollection();
        services.AddArgon2idPasswordHasherWithMigration<TestUser>(o => o.MemorySizeKib = 8192);
        using ServiceProvider sp = services.BuildServiceProvider();

        var hasher = sp.GetRequiredService<IPasswordHasher<TestUser>>();
        Assert.IsType<MigratingPasswordHasher<TestUser>>(hasher);
    }

    [Fact]
    public void DI_registers_argon2id_as_the_password_hasher()
    {
        var services = new ServiceCollection();
        services.AddArgon2idPasswordHasher<TestUser>(o => o.MemorySizeKib = 8192);
        using ServiceProvider sp = services.BuildServiceProvider();

        var hasher = sp.GetRequiredService<IPasswordHasher<TestUser>>();
        Assert.IsType<Argon2idPasswordHasher<TestUser>>(hasher);

        // And it actually round-trips.
        var user = new TestUser();
        string hash = hasher.HashPassword(user, "pw");
        Assert.Equal(PasswordVerificationResult.Success, hasher.VerifyHashedPassword(user, hash, "pw"));
    }
}
