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

    /// <summary>
    /// The verification-side acceptance bounds, pinned exactly at both edges of
    /// every axis. The parsed work factors drive a real Argon2id computation in
    /// <c>Verify</c>, so each axis must reject one-past-the-bound while still
    /// accepting the bound itself (a legitimate, if exotic, stored hash).
    /// </summary>
    [Theory]
    // Memory: [8 KiB, 4 GiB], and never below Argon2's structural m ≥ 8·p.
    [InlineData(8, 1, 1, 16, 32, true)]
    [InlineData(7, 1, 1, 16, 32, false)]
    [InlineData(4194304, 1, 1, 16, 32, true)]
    [InlineData(4194305, 1, 1, 16, 32, false)]
    [InlineData(64, 1, 8, 16, 32, true)]   // m = 8·p exactly
    [InlineData(63, 1, 8, 16, 32, false)]  // m < 8·p
    // Iterations: [1, 512].
    [InlineData(8192, 512, 1, 16, 32, true)]
    [InlineData(8192, 513, 1, 16, 32, false)]
    [InlineData(8192, 0, 1, 16, 32, false)]
    // Parallelism: [1, 64].
    [InlineData(8192, 1, 64, 16, 32, true)]
    [InlineData(8192, 1, 65, 16, 32, false)]
    [InlineData(8192, 1, 0, 16, 32, false)]
    // Salt: [8, 64] bytes.
    [InlineData(8192, 1, 1, 8, 32, true)]
    [InlineData(8192, 1, 1, 7, 32, false)]
    [InlineData(8192, 1, 1, 64, 32, true)]
    [InlineData(8192, 1, 1, 65, 32, false)]
    // Tag: [12, 512] bytes.
    [InlineData(8192, 1, 1, 16, 12, true)]
    [InlineData(8192, 1, 1, 16, 11, false)]
    [InlineData(8192, 1, 1, 16, 512, true)]
    [InlineData(8192, 1, 1, 16, 513, false)]
    public void TryParse_enforces_acceptance_bounds_at_the_exact_edges(
        int memory, int iterations, int parallelism, int saltBytes, int hashBytes, bool expected)
    {
        string phc = $"$argon2id$v=19$m={memory},t={iterations},p={parallelism}"
            + $"${B64(saltBytes)}${B64(hashBytes)}";

        Assert.Equal(expected, PhcString.TryParse(phc, out PhcString? parsed));
        if (expected)
        {
            Assert.NotNull(parsed);
            Assert.Equal(memory, parsed!.MemorySizeKib);
            Assert.Equal(saltBytes, parsed.Salt.Length);
            Assert.Equal(hashBytes, parsed.Hash.Length);
        }
        else
        {
            Assert.Null(parsed);
        }
    }

    /// <summary>
    /// <see cref="Convert.TryFromBase64String(string, Span{byte}, out int)"/>
    /// silently skips whitespace and tolerates non-zero trailing bits, either of
    /// which would let distinct stored strings alias to the same decoded bytes.
    /// The canonicality pin (decode → re-encode → ordinal-equal) must reject both.
    /// </summary>
    [Theory]
    // 4 spaces keep both raw and effective lengths ≡ 0 (mod 4), so this reaches
    // the decoder instead of dying on the length check — the pin must catch it.
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$AAAAAAAA    AAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    // "c29tZXNhbHR" decodes to the same 8 bytes as the canonical "c29tZXNhbHQ"
    // ("somesalt") because .NET ignores the non-zero trailing bits in 'R'.
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHR$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void TryParse_rejects_non_canonical_base64(string value)
    {
        Assert.False(PhcString.TryParse(value, out PhcString? parsed));
        Assert.Null(parsed);
    }

    /// <summary>
    /// Numeric canonicality: <c>NumberStyles.None</c> tolerates leading zeros,
    /// so without an explicit rejection "m=08192" would parse to the same
    /// components as "m=8192" — a second accepted spelling of the same hash,
    /// breaching the one-encoding-per-value pin.
    /// </summary>
    [Theory]
    [InlineData("$argon2id$v=19$m=08192,t=1,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=8192,t=01,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=01$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=019$m=8192,t=1,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void TryParse_rejects_leading_zero_aliases_in_numeric_fields(string value)
    {
        Assert.False(PhcString.TryParse(value, out PhcString? parsed));
        Assert.Null(parsed);
    }

    [Fact]
    public void TryParse_rejects_oversized_base64_fields_before_decoding()
    {
        // A poisoned multi-kilobyte field must die on the length gate, not get
        // padded + decoded + re-encoded in full first. 100k chars of valid
        // base64 alphabet, length ≡ 0 (mod 4), decoding to 75k bytes — far
        // beyond the 512-byte tag ceiling.
        string huge = new string('A', 100_000);
        Assert.False(PhcString.TryParse(
            $"$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHQ${huge}", out PhcString? parsed));
        Assert.Null(parsed);
    }

    [Fact]
    public void TryParse_accepts_the_canonical_form_of_the_rejected_alias()
    {
        // Companion to the non-canonical rejection above: the canonical spelling
        // of the same salt bytes parses fine, proving the pin rejects the
        // encoding, not the value.
        Assert.True(PhcString.TryParse(
            "$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            out PhcString? parsed));
        Assert.Equal("somesalt"u8.ToArray(), parsed!.Salt);
    }

    /// <summary>Canonical unpadded base64 of <paramref name="byteCount"/> zero bytes.</summary>
    private static string B64(int byteCount) =>
        Convert.ToBase64String(new byte[byteCount]).TrimEnd('=');
}
