using System.Text;
using PostQuantum.Identity.Internal;
using Xunit;

namespace PostQuantum.Identity.Tests;

/// <summary>
/// Deterministic generative (property-based / fuzz-style) corpus for the PHC
/// parser and the verify path built on it. Every case is derived from a fixed
/// xorshift32 seed, so a failure reproduces identically on every machine and
/// every run — the failing case index is baked into the assertion message.
/// No third-party property-testing dependency is required.
///
/// Invariants pinned here:
///  1. Roundtrip — Format → TryParse recovers every field exactly, across the
///     full verification-acceptance bounds (not just the emitter's range).
///  2. Total safety — TryParse never throws, on mutations of valid hashes or
///     on outright garbage.
///  3. Bounded acceptance — anything TryParse accepts sits inside the
///     documented acceptance bounds, so Verify can never be handed work
///     factors it shouldn't spend.
///  4. Fail-closed verification — no mutation of a stored hash ever verifies.
///     (The canonicality pin makes this strict: distinct strings can no longer
///     alias to the same decoded components.)
/// </summary>
public class PhcStringPropertyTests
{
    private const string Password = "correct horse battery staple";

    [Fact]
    public void Roundtrip_holds_for_random_components_across_the_acceptance_bounds()
    {
        var rng = new XorShift32(seed: 0x9106);

        for (int i = 0; i < 1_000; i++)
        {
            int parallelism = rng.Next(PhcString.MinDegreeOfParallelism, PhcString.MaxDegreeOfParallelism + 1);
            int memory = rng.Next(8 * parallelism, PhcString.MaxMemorySizeKib + 1);
            int iterations = rng.Next(PhcString.MinIterations, PhcString.MaxIterations + 1);
            byte[] salt = rng.NextBytes(rng.Next(PhcString.MinSaltSizeBytes, PhcString.MaxSaltSizeBytes + 1));
            byte[] hash = rng.NextBytes(rng.Next(PhcString.MinHashSizeBytes, PhcString.MaxHashSizeBytes + 1));

            // Format reads the fields directly; Validate() is not in play here,
            // so the roundtrip is exercised across the full *acceptance* range,
            // which is wider than the emitter's configurable range.
            var options = new Argon2idOptions
            {
                MemorySizeKib = memory,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
            };

            string phc = PhcString.Format(options, salt, hash);

            Assert.True(PhcString.TryParse(phc, out PhcString? parsed), $"case {i}: failed to parse own output: {phc}");
            Assert.Equal(memory, parsed!.MemorySizeKib);
            Assert.Equal(iterations, parsed.Iterations);
            Assert.Equal(parallelism, parsed.DegreeOfParallelism);
            Assert.Equal(salt, parsed.Salt);
            Assert.Equal(hash, parsed.Hash);
        }
    }

    [Fact]
    public void TryParse_never_throws_and_stays_bounded_on_mutated_hashes()
    {
        var rng = new XorShift32(seed: 0xF19A);
        string[] bases =
        [
            PhcString.Format(TestDefaults.FastOptions(), rng.NextBytes(16), rng.NextBytes(32)),
            PhcString.Format(new Argon2idOptions(), rng.NextBytes(16), rng.NextBytes(32)),
            "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
        ];

        for (int i = 0; i < 3_000; i++)
        {
            string mutated = Mutate(bases[i % bases.Length], rng);

            // Must never throw; anything accepted must be inside the bounds.
            bool ok = PhcString.TryParse(mutated, out PhcString? parsed);
            if (ok)
            {
                AssertWithinAcceptanceBounds(parsed!, i, mutated);
            }
            else
            {
                Assert.Null(parsed);
            }
        }
    }

    [Fact]
    public void TryParse_never_throws_and_stays_bounded_on_random_garbage()
    {
        // Alphabet is deliberately hostile: structural characters ('$', ',', '='),
        // base64 alphabet, digits, whitespace, NUL, and non-ASCII.
        const string alphabet = "$avmtp=,0123456789AZaz+/ \t\0é�";
        var rng = new XorShift32(seed: 0xC0FFEE);

        for (int i = 0; i < 3_000; i++)
        {
            int length = rng.Next(0, 121);
            var sb = new StringBuilder(length);
            for (int c = 0; c < length; c++)
            {
                sb.Append(alphabet[rng.Next(0, alphabet.Length)]);
            }

            string garbage = sb.ToString();
            bool ok = PhcString.TryParse(garbage, out PhcString? parsed);
            if (ok)
            {
                AssertWithinAcceptanceBounds(parsed!, i, garbage);
            }
        }
    }

    [Fact]
    public void Verify_fails_closed_and_never_throws_on_every_mutation_of_a_stored_hash()
    {
        var hasher = new Argon2idPasswordHasher(TestDefaults.FastOptions());
        string stored = hasher.HashPassword(Password);
        var rng = new XorShift32(seed: 0xBADD);

        // The stored value itself must verify — the mutations below are judged
        // against a known-good baseline, not a vacuously-failing one.
        Assert.True(hasher.Verify(Password, stored).Success);

        for (int i = 0; i < 300; i++)
        {
            string mutated = Mutate(stored, rng);
            if (mutated == stored)
            {
                continue; // a mutation can no-op (e.g. replacing a char with itself)
            }

            // The whole point of the canonicality pin: any string other than the
            // exact stored value either fails to parse or decodes to different
            // components, so it can never verify — and never throws.
            VerifyResult result = hasher.Verify(Password, mutated);
            Assert.False(result.Success, $"case {i}: mutated hash verified: {mutated}");
        }
    }

    private static void AssertWithinAcceptanceBounds(PhcString parsed, int caseIndex, string input)
    {
        string detail = $"case {caseIndex}: out-of-bounds accept for: {input}";
        Assert.True(parsed.MemorySizeKib is >= PhcString.MinMemorySizeKib and <= PhcString.MaxMemorySizeKib, detail);
        Assert.True(parsed.Iterations is >= PhcString.MinIterations and <= PhcString.MaxIterations, detail);
        Assert.True(parsed.DegreeOfParallelism is >= PhcString.MinDegreeOfParallelism and <= PhcString.MaxDegreeOfParallelism, detail);
        Assert.True(parsed.MemorySizeKib >= 8 * parsed.DegreeOfParallelism, detail);
        Assert.True(parsed.Salt.Length is >= PhcString.MinSaltSizeBytes and <= PhcString.MaxSaltSizeBytes, detail);
        Assert.True(parsed.Hash.Length is >= PhcString.MinHashSizeBytes and <= PhcString.MaxHashSizeBytes, detail);
    }

    /// <summary>
    /// One random structural edit: substitute, insert, delete, transpose, or
    /// truncate. Substitutions draw from a hostile alphabet biased toward
    /// characters with structural meaning in the PHC grammar.
    /// </summary>
    private static string Mutate(string value, XorShift32 rng)
    {
        const string hostile = "$=,. aA0Zz9+/\0";
        if (value.Length == 0)
        {
            return hostile[rng.Next(0, hostile.Length)].ToString();
        }

        int position = rng.Next(0, value.Length);
        return rng.Next(0, 5) switch
        {
            0 => value[..position] + hostile[rng.Next(0, hostile.Length)] + value[(position + 1)..],
            1 => value[..position] + hostile[rng.Next(0, hostile.Length)] + value[position..],
            2 => value[..position] + value[(position + 1)..],
            3 => position + 1 < value.Length
                ? value[..position] + value[position + 1] + value[position] + value[(position + 2)..]
                : value,
            _ => value[..position],
        };
    }

    /// <summary>
    /// Minimal xorshift32 PRNG (Marsaglia). Deterministic for a given seed on
    /// every runtime and architecture, unlike <see cref="Random"/>, whose seeded
    /// algorithm is not contractually stable across .NET versions.
    /// </summary>
    private sealed class XorShift32(uint seed)
    {
        private uint _state = seed == 0 ? 0x9E3779B9u : seed;

        private uint NextUInt()
        {
            uint x = _state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            return _state = x;
        }

        /// <summary>Uniform-ish integer in [minInclusive, maxExclusive).</summary>
        public int Next(int minInclusive, int maxExclusive) =>
            minInclusive + (int)(NextUInt() % (uint)(maxExclusive - minInclusive));

        public byte[] NextBytes(int count)
        {
            byte[] bytes = new byte[count];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)NextUInt();
            }

            return bytes;
        }
    }
}
