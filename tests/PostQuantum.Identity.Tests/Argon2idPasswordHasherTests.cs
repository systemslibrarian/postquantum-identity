using Xunit;

namespace PostQuantum.Identity.Tests;

public class Argon2idPasswordHasherTests
{
    private static Argon2idPasswordHasher NewHasher(Argon2idOptions? options = null) =>
        new(options ?? TestDefaults.FastOptions());

    [Fact]
    public void HashPassword_produces_argon2id_phc_string()
    {
        string hash = NewHasher().HashPassword("correct horse battery staple");
        Assert.StartsWith("$argon2id$v=19$", hash, StringComparison.Ordinal);
    }

    [Fact]
    public void HashPassword_is_salted_so_two_hashes_differ()
    {
        var hasher = NewHasher();
        Assert.NotEqual(hasher.HashPassword("same"), hasher.HashPassword("same"));
    }

    [Fact]
    public void Verify_succeeds_for_correct_password()
    {
        var hasher = NewHasher();
        string hash = hasher.HashPassword("s3cret");
        VerifyResult result = hasher.Verify("s3cret", hash);
        Assert.True(result.Success);
        Assert.False(result.NeedsRehash);
    }

    [Fact]
    public void Verify_fails_for_wrong_password()
    {
        var hasher = NewHasher();
        string hash = hasher.HashPassword("s3cret");
        Assert.False(hasher.Verify("wrong", hash).Success);
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("$argon2id$v=19$broken")]
    public void Verify_fails_closed_on_malformed_stored_hash(string stored)
    {
        Assert.Equal(VerifyResult.Failed, NewHasher().Verify("whatever", stored));
    }

    [Fact]
    public void Verify_flags_rehash_when_stored_params_are_weaker()
    {
        // Stored with weak params...
        string weak = NewHasher(new Argon2idOptions { MemorySizeKib = 8192, Iterations = 1 })
            .HashPassword("pw");

        // ...verified by a hasher configured stronger -> rehash requested.
        var strong = NewHasher(new Argon2idOptions { MemorySizeKib = 16384, Iterations = 2 });
        VerifyResult result = strong.Verify("pw", weak);

        Assert.True(result.Success);
        Assert.True(result.NeedsRehash);
    }

    [Fact]
    public void NeedsRehash_is_true_for_foreign_or_legacy_hash()
    {
        // A stock ASP.NET Core Identity PBKDF2 hash is not argon2id PHC.
        Assert.True(NewHasher().NeedsRehash("AQAAAAIAAYagAAAAE..."));
    }

    [Fact]
    public void NeedsRehash_is_false_for_current_params()
    {
        var hasher = NewHasher();
        Assert.False(hasher.NeedsRehash(hasher.HashPassword("pw")));
    }

    [Fact]
    public void Constructor_rejects_insecure_options()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new Argon2idPasswordHasher(new Argon2idOptions { MemorySizeKib = 1024 }));
    }

    [Fact]
    public void HashPassword_rejects_null_password()
    {
        Assert.Throws<ArgumentNullException>(() => NewHasher().HashPassword(null!));
    }
}
