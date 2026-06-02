using PostQuantum.Identity.Internal;
using Xunit;

namespace PostQuantum.Identity.Tests;

public class PhcStringTests
{
    [Fact]
    public void Format_then_TryParse_roundtrips_all_fields()
    {
        var options = new Argon2idOptions { MemorySizeKib = 65536, Iterations = 3, DegreeOfParallelism = 2 };
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        byte[] hash = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

        string phc = PhcString.Format(options, salt, hash);

        Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=2$", phc, StringComparison.Ordinal);
        Assert.True(PhcString.TryParse(phc, out PhcString? parsed));
        Assert.NotNull(parsed);
        Assert.Equal(65536, parsed!.MemorySizeKib);
        Assert.Equal(3, parsed.Iterations);
        Assert.Equal(2, parsed.DegreeOfParallelism);
        Assert.Equal(salt, parsed.Salt);
        Assert.Equal(hash, parsed.Hash);
    }

    [Fact]
    public void Format_emits_unpadded_base64_in_salt_and_hash_segments()
    {
        // The parameter section legitimately contains '=' (v=19, m=, t=, p=); only
        // the trailing salt and hash segments must be padding-free base64.
        string phc = PhcString.Format(TestDefaults.FastOptions(), new byte[16], new byte[32]);
        string[] segments = phc.Split('$');
        Assert.DoesNotContain('=', segments[4]); // salt
        Assert.DoesNotContain('=', segments[5]); // hash
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-phc-string")]
    [InlineData("$argon2i$v=19$m=8192,t=1,p=1$AAAA$AAAA")]   // wrong variant
    [InlineData("$argon2id$v=16$m=8192,t=1,p=1$AAAA$AAAA")]  // wrong version
    [InlineData("$argon2id$v=19$m=8192,t=1$AAAA$AAAA")]      // missing p
    [InlineData("$argon2id$v=19$m=x,t=1,p=1$AAAA$AAAA")]     // non-numeric m
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$$AAAA")]      // empty salt
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$!!!!$AAAA")]  // invalid base64
    public void TryParse_fails_closed_on_malformed_input(string? value)
    {
        Assert.False(PhcString.TryParse(value, out PhcString? parsed));
        Assert.Null(parsed);
    }
}
