using System.Globalization;
using System.Text;
using Konscious.Security.Cryptography;
using PostQuantum.Identity.Internal;
using Xunit;

namespace PostQuantum.Identity.Tests;

/// <summary>
/// Known Answer Tests (KATs) for the Argon2id surface. These pin our engine,
/// PHC format, and verification path to published cryptographic vectors so that
/// any drift from the spec — or from the de-facto Argon2 interop format used by
/// the reference CLI and libsodium — fails the build.
/// </summary>
/// <remarks>
/// <para>Three layers of assurance are pinned here:</para>
/// <list type="number">
///   <item>The RFC 9106 §5.3 Argon2id reference vector (keyed + associated-data
///         path) — proves the underlying Argon2id computation matches the
///         standard, including the rarely-tested secret and AD branches.</item>
///   <item>A canonical reference-<c>argon2</c>-CLI PHC string that must verify
///         through our hasher — proves PHC parsing and Argon2id compute together
///         are wire-compatible with the standard tooling.</item>
///   <item>Compute-then-format round-trips across multiple work-factor profiles
///         (OWASP minimum, RFC 9106 second recommended, libsodium MODERATE-ish) —
///         proves the PHC emitter and parser produce strings that any
///         spec-compliant verifier (including our own) accepts.</item>
/// </list>
/// </remarks>
public class Argon2idKnownAnswerTests
{
    private static byte[] Repeat(byte value, int count)
    {
        var b = new byte[count];
        Array.Fill(b, value);
        return b;
    }

    private static byte[] FromHex(string hex)
    {
        hex = hex.Replace(" ", string.Empty, StringComparison.Ordinal);
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = byte.Parse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return bytes;
    }

    /// <summary>
    /// RFC 9106 §5.3 Argon2id reference vector: v=19, m=32 KiB, t=3, p=4, 32-byte
    /// tag, with a secret key and associated data. Proves the underlying Argon2id
    /// computation (incl. the keyed + AD paths) matches the standard.
    /// </summary>
    [Fact]
    public void Rfc9106_argon2id_reference_vector()
    {
        byte[] password = Repeat(0x01, 32);
        byte[] salt = Repeat(0x02, 16);
        byte[] secret = Repeat(0x03, 8);
        byte[] associatedData = Repeat(0x04, 12);

        using var argon2 = new Argon2id(password)
        {
            Salt = salt,
            KnownSecret = secret,
            AssociatedData = associatedData,
            DegreeOfParallelism = 4,
            Iterations = 3,
            MemorySize = 32,
        };

        byte[] tag = argon2.GetBytes(32);

        byte[] expected = FromHex(
            "0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 " +
            "d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59");
        Assert.Equal(expected, tag);
    }

    /// <summary>
    /// Interop KAT: a PHC string produced by the canonical reference <c>argon2</c>
    /// CLI (<c>echo -n "password" | argon2 somesalt -id -t 2 -m 16 -p 1 -l 32</c>)
    /// must verify with our hasher. Proves PHC parsing + Argon2id are wire-
    /// compatible with the de-facto standard tooling.
    /// </summary>
    [Fact]
    public void Verifies_phc_string_from_reference_argon2_cli()
    {
        const string referencePhc =
            "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";

        var hasher = new Argon2idPasswordHasher(TestDefaults.FastOptions());

        Assert.True(hasher.Verify("password", referencePhc).Success);
        Assert.False(hasher.Verify("wrong", referencePhc).Success);
    }

    /// <summary>
    /// The raw 32-byte tag for the reference CLI vector, computed directly, equals
    /// the published value (hex <c>0931...3cf7</c>) — a second, encoding-free check
    /// of the same parameters.
    /// </summary>
    [Fact]
    public void Reference_cli_raw_tag_matches()
    {
        using var argon2 = new Argon2id(Encoding.ASCII.GetBytes("password"))
        {
            Salt = Encoding.ASCII.GetBytes("somesalt"),
            DegreeOfParallelism = 1,
            Iterations = 2,
            MemorySize = 65536,
        };

        byte[] tag = argon2.GetBytes(32);
        byte[] expected = FromHex("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7");
        Assert.Equal(expected, tag);
    }

    /// <summary>
    /// PHC emitter pins the wire format to a known shape. With a fixed
    /// password / salt / parameters / tag, the emitted string must exactly equal
    /// the reference-CLI PHC encoding — this catches any drift in the formatter
    /// (segment count, version field, comma-ordering, padding stripping).
    /// </summary>
    [Fact]
    public void Phc_emitter_pins_reference_cli_wire_format()
    {
        const string expectedPhc =
            "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";

        // Compute the same tag the reference CLI did, then format through our emitter.
        byte[] salt = Encoding.ASCII.GetBytes("somesalt");
        using var argon2 = new Argon2id(Encoding.ASCII.GetBytes("password"))
        {
            Salt = salt,
            DegreeOfParallelism = 1,
            Iterations = 2,
            MemorySize = 65536,
        };
        byte[] tag = argon2.GetBytes(32);

        var opts = new Argon2idOptions { MemorySizeKib = 65536, Iterations = 2, DegreeOfParallelism = 1 };
        string emitted = PhcString.Format(opts, salt, tag);

        Assert.Equal(expectedPhc, emitted);
    }

    /// <summary>
    /// Compute-then-format-then-verify cycle across multiple published-style
    /// work-factor profiles. For each, we compute the raw tag with Konscious,
    /// emit a PHC string, parse it back, and confirm the parsed parameters and
    /// tag bytes match the input — proving emitter + parser are exact inverses
    /// on every realistic profile we expect to see in the wild.
    /// </summary>
    [Theory]
    [InlineData(19456, 2, 1, 16, 32)] // OWASP 2024 minimum (Argon2id, 19 MiB, t=2)
    [InlineData(65536, 3, 1, 16, 32)] // Library default / RFC 9106 second profile shape
    [InlineData(131072, 4, 1, 16, 32)] // Stronger / latency-tolerant deployments
    [InlineData(8192, 1, 1, 16, 16)]   // Documented minimum allowed by Argon2idOptions
    public void Phc_roundtrips_for_published_work_factor_profiles(
        int memoryKib, int iterations, int parallelism, int saltLen, int tagLen)
    {
        byte[] password = Encoding.UTF8.GetBytes("correct horse battery staple");
        byte[] salt = Repeat(0x5A, saltLen);

        using var argon2 = new Argon2id(password)
        {
            Salt = salt,
            DegreeOfParallelism = parallelism,
            Iterations = iterations,
            MemorySize = memoryKib,
        };
        byte[] tag = argon2.GetBytes(tagLen);

        var opts = new Argon2idOptions
        {
            MemorySizeKib = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
            SaltSizeBytes = saltLen,
            HashSizeBytes = tagLen,
        };

        string phc = PhcString.Format(opts, salt, tag);
        Assert.True(PhcString.TryParse(phc, out PhcString? parsed));
        Assert.NotNull(parsed);
        Assert.Equal(memoryKib, parsed!.MemorySizeKib);
        Assert.Equal(iterations, parsed.Iterations);
        Assert.Equal(parallelism, parsed.DegreeOfParallelism);
        Assert.Equal(salt, parsed.Salt);
        Assert.Equal(tag, parsed.Hash);

        // And the hasher itself accepts the round-tripped string for the same password.
        var hasher = new Argon2idPasswordHasher(opts);
        Assert.True(hasher.Verify("correct horse battery staple", phc).Success);
    }

    /// <summary>
    /// Single-byte tamper of the tag in a known-good PHC string must fail to
    /// verify, demonstrating the fail-closed property of the verification path.
    /// </summary>
    [Fact]
    public void Single_byte_tag_tamper_rejects_verification()
    {
        const string goodPhc =
            "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";

        // Flip the last meaningful character of the tag segment.
        char flipped = goodPhc[^1] == 'A' ? 'B' : 'A';
        string tampered = goodPhc[..^1] + flipped;

        var hasher = new Argon2idPasswordHasher(TestDefaults.FastOptions());
        Assert.False(hasher.Verify("password", tampered).Success);
    }
}
