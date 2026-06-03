using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PostQuantum.Identity.DependencyInjection;
using Xunit;

namespace PostQuantum.Identity.Tests;

/// <summary>
/// End-to-end integration tests proving the documented migration contract
/// through a real <see cref="UserManager{TUser}"/> — not just the password
/// hasher adapter in isolation. Reads like a small simulation of the real
/// "user shows up after deploy, signs in, and their stored hash gets upgraded"
/// flow, with no migration job, no flag day, no forced reset.
/// </summary>
public class MigrationUserManagerIntegrationTests
{
    private sealed class TestUser
    {
        public string Id { get; init; } = Guid.NewGuid().ToString();
        public string? UserName { get; set; }
        public string? NormalizedUserName { get; set; }
        public string? PasswordHash { get; set; }
    }

    /// <summary>
    /// Minimal in-memory user store. Implements only the surfaces
    /// <see cref="UserManager{TUser}"/> hits in the
    /// CheckPassword → UpdatePasswordHash flow that the migration relies on.
    /// </summary>
    private sealed class InMemoryUserStore : IUserStore<TestUser>, IUserPasswordStore<TestUser>
    {
        private readonly Dictionary<string, TestUser> _byId = new(StringComparer.Ordinal);
        private readonly Dictionary<string, TestUser> _byName = new(StringComparer.Ordinal);

        public Task<string> GetUserIdAsync(TestUser user, CancellationToken ct) => Task.FromResult(user.Id);
        public Task<string?> GetUserNameAsync(TestUser user, CancellationToken ct) => Task.FromResult(user.UserName);
        public Task SetUserNameAsync(TestUser user, string? name, CancellationToken ct)
        {
            user.UserName = name;
            return Task.CompletedTask;
        }
        public Task<string?> GetNormalizedUserNameAsync(TestUser user, CancellationToken ct) => Task.FromResult(user.NormalizedUserName);
        public Task SetNormalizedUserNameAsync(TestUser user, string? name, CancellationToken ct)
        {
            user.NormalizedUserName = name;
            if (name is not null)
            {
                _byName[name] = user;
            }

            return Task.CompletedTask;
        }
        public Task<IdentityResult> CreateAsync(TestUser user, CancellationToken ct)
        {
            _byId[user.Id] = user;
            if (user.NormalizedUserName is not null)
            {
                _byName[user.NormalizedUserName] = user;
            }

            return Task.FromResult(IdentityResult.Success);
        }
        public Task<IdentityResult> UpdateAsync(TestUser user, CancellationToken ct)
        {
            _byId[user.Id] = user;
            return Task.FromResult(IdentityResult.Success);
        }
        public Task<IdentityResult> DeleteAsync(TestUser user, CancellationToken ct)
        {
            _byId.Remove(user.Id);
            return Task.FromResult(IdentityResult.Success);
        }
        public Task<TestUser?> FindByIdAsync(string userId, CancellationToken ct)
            => Task.FromResult(_byId.TryGetValue(userId, out TestUser? u) ? u : null);
        public Task<TestUser?> FindByNameAsync(string normalizedUserName, CancellationToken ct)
            => Task.FromResult(_byName.TryGetValue(normalizedUserName, out TestUser? u) ? u : null);

        // Password store surface.
        public Task SetPasswordHashAsync(TestUser user, string? hash, CancellationToken ct)
        {
            user.PasswordHash = hash;
            return Task.CompletedTask;
        }
        public Task<string?> GetPasswordHashAsync(TestUser user, CancellationToken ct) => Task.FromResult(user.PasswordHash);
        public Task<bool> HasPasswordAsync(TestUser user, CancellationToken ct) => Task.FromResult(user.PasswordHash is not null);

        public void Dispose() { }
    }

    private static UserManager<TestUser> BuildUserManager(out InMemoryUserStore store)
    {
        store = new InMemoryUserStore();
        ServiceCollection services = new();
        services.AddSingleton<IUserStore<TestUser>>(store);
        services.AddLogging();
        services.AddIdentityCore<TestUser>(o =>
        {
            o.Password.RequireDigit = false;
            o.Password.RequireLowercase = false;
            o.Password.RequireUppercase = false;
            o.Password.RequireNonAlphanumeric = false;
            o.Password.RequiredLength = 1;
        })
            .AddArgon2idPasswordHasherWithMigration<TestUser>(Argon2idOptions.OwaspMinimum());

        ServiceProvider sp = services.BuildServiceProvider();
        return sp.GetRequiredService<UserManager<TestUser>>();
    }

    /// <summary>
    /// The full migration: a user is created with the STOCK PBKDF2 hasher, their
    /// row is then verified through the migrating-hasher-equipped UserManager,
    /// CheckPassword succeeds, and on the next read the stored hash is already
    /// Argon2id — i.e. UserManager rewrote it as part of the verification flow.
    /// </summary>
    [Fact]
    public async Task UserManager_rewrites_legacy_pbkdf2_hash_as_argon2id_on_successful_sign_in()
    {
        UserManager<TestUser> users = BuildUserManager(out InMemoryUserStore store);

        // Seed: a user whose stored hash was produced by the stock PBKDF2 hasher.
        var legacyHasher = new PasswordHasher<TestUser>();
        var seeded = new TestUser { UserName = "ada", NormalizedUserName = "ADA" };
        seeded.PasswordHash = legacyHasher.HashPassword(seeded, "Lovelace#1843");
        await store.CreateAsync(seeded, CancellationToken.None);

        // Pre-condition: the stored hash is PBKDF2, NOT Argon2id.
        TestUser? before = await users.FindByNameAsync("ada");
        Assert.NotNull(before);
        Assert.False(Argon2idPasswordHasher.IsArgon2idHash(before!.PasswordHash));

        // Act: this is the "user signs in" call in any Identity-based app.
        bool ok = await users.CheckPasswordAsync(before, "Lovelace#1843");
        Assert.True(ok);

        // Post-condition: the stored hash has been rewritten as Argon2id.
        TestUser? after = await users.FindByIdAsync(before.Id);
        Assert.NotNull(after);
        Assert.True(Argon2idPasswordHasher.IsArgon2idHash(after!.PasswordHash));

        // Sanity: the new hash also verifies correctly under the next sign-in.
        Assert.True(await users.CheckPasswordAsync(after, "Lovelace#1843"));
    }

    /// <summary>
    /// A wrong password through the migrating UserManager flow must NOT trigger
    /// a rewrite (otherwise we'd be silently masking failed sign-ins as
    /// successful upgrades). The row must stay PBKDF2.
    /// </summary>
    [Fact]
    public async Task UserManager_does_not_rewrite_when_password_check_fails()
    {
        UserManager<TestUser> users = BuildUserManager(out InMemoryUserStore store);

        var legacyHasher = new PasswordHasher<TestUser>();
        var seeded = new TestUser { UserName = "ada", NormalizedUserName = "ADA" };
        seeded.PasswordHash = legacyHasher.HashPassword(seeded, "Lovelace#1843");
        await store.CreateAsync(seeded, CancellationToken.None);

        bool ok = await users.CheckPasswordAsync(seeded, "WRONG");
        Assert.False(ok);

        TestUser? after = await users.FindByIdAsync(seeded.Id);
        Assert.NotNull(after);
        Assert.False(Argon2idPasswordHasher.IsArgon2idHash(after!.PasswordHash));
    }

    /// <summary>
    /// New users created through the UserManager after the migration is deployed
    /// are hashed with Argon2id immediately — no PBKDF2 detour.
    /// </summary>
    [Fact]
    public async Task UserManager_hashes_new_users_with_argon2id_immediately()
    {
        UserManager<TestUser> users = BuildUserManager(out _);

        IdentityResult created = await users.CreateAsync(
            new TestUser { UserName = "bob", NormalizedUserName = "BOB" }, "Builder#2020");
        Assert.True(created.Succeeded);

        TestUser? bob = await users.FindByNameAsync("bob");
        Assert.NotNull(bob);
        Assert.True(Argon2idPasswordHasher.IsArgon2idHash(bob!.PasswordHash));
    }
}
