using System.Globalization;
using Konscious.Security.Cryptography;
using Xunit;

namespace PostQuantum.Identity.Tests;

/// <summary>
/// Known Answer Tests (KATs) proving the Argon2id engine this library builds on
/// produces spec-correct output, and that our PHC verification interoperates with
/// hashes produced by the reference <c>argon2</c> tooling.
/// </summary>
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
        using var argon2 = new Argon2id(System.Text.Encoding.ASCII.GetBytes("password"))
        {
            Salt = System.Text.Encoding.ASCII.GetBytes("somesalt"),
            DegreeOfParallelism = 1,
            Iterations = 2,
            MemorySize = 65536,
        };

        byte[] tag = argon2.GetBytes(32);
        byte[] expected = FromHex("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7");
        Assert.Equal(expected, tag);
    }
}
