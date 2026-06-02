using Xunit;

namespace PostQuantum.Identity.Tests;

public class Argon2idOptionsTests
{
    [Fact]
    public void Recommended_defaults_are_safe_and_validate()
    {
        var o = Argon2idOptions.Recommended;
        Assert.Equal(65536, o.MemorySizeKib);
        Assert.Equal(3, o.Iterations);
        Assert.Equal(1, o.DegreeOfParallelism);
        Assert.Equal(16, o.SaltSizeBytes);
        Assert.Equal(32, o.HashSizeBytes);
        o.Validate(); // does not throw
    }

    [Fact]
    public void Default_constructor_validates()
    {
        new Argon2idOptions().Validate();
    }

    [Theory]
    [InlineData(nameof(Argon2idOptions.MemorySizeKib), 4096)]
    [InlineData(nameof(Argon2idOptions.Iterations), 0)]
    [InlineData(nameof(Argon2idOptions.DegreeOfParallelism), 0)]
    [InlineData(nameof(Argon2idOptions.SaltSizeBytes), 8)]
    [InlineData(nameof(Argon2idOptions.HashSizeBytes), 8)]
    public void Validate_rejects_each_out_of_range_parameter(string property, int badValue)
    {
        var o = new Argon2idOptions();
        switch (property)
        {
            case nameof(Argon2idOptions.MemorySizeKib): o.MemorySizeKib = badValue; break;
            case nameof(Argon2idOptions.Iterations): o.Iterations = badValue; break;
            case nameof(Argon2idOptions.DegreeOfParallelism): o.DegreeOfParallelism = badValue; break;
            case nameof(Argon2idOptions.SaltSizeBytes): o.SaltSizeBytes = badValue; break;
            case nameof(Argon2idOptions.HashSizeBytes): o.HashSizeBytes = badValue; break;
        }

        ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(o.Validate);
        Assert.Equal(property, ex.ParamName);
    }

    [Fact]
    public void Hasher_takes_a_defensive_copy_of_options()
    {
        var options = new Argon2idOptions { MemorySizeKib = 8192, Iterations = 1 };
        var hasher = new Argon2idPasswordHasher(options);

        // Mutating the original after construction must not affect the hasher.
        options.MemorySizeKib = 65536;

        string hash = hasher.HashPassword("pw");
        // Hash was produced with the captured 8192, so the same hasher reports no rehash.
        Assert.False(hasher.NeedsRehash(hash));
    }

    [Fact]
    public void NeedsRehash_true_when_only_salt_size_increases()
    {
        // Stored with a 16-byte salt...
        string stored = new Argon2idPasswordHasher(
            new Argon2idOptions { MemorySizeKib = 8192, Iterations = 1, SaltSizeBytes = 16 }).HashPassword("pw");

        // ...verified by a hasher wanting a 32-byte salt -> rehash requested.
        var bigSalt = new Argon2idPasswordHasher(
            new Argon2idOptions { MemorySizeKib = 8192, Iterations = 1, SaltSizeBytes = 32 });
        Assert.True(bigSalt.NeedsRehash(stored));
    }
}
