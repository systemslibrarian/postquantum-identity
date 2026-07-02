using System.Collections.Concurrent;
using PostQuantum.Identity.Internal;
using Xunit;

namespace PostQuantum.Identity.Tests;

/// <summary>
/// Production-scenario regression tests: concurrent verification correctness
/// under load, rehash-threshold behavior across every parameter axis, and a
/// hand-rolled fuzz-style corpus for <see cref="PhcString.TryParse"/> proving
/// it can't be coaxed into a partial match by adversarial input.
/// </summary>
public class Argon2idProductionScenarioTests
{
    private static Argon2idPasswordHasher NewFastHasher() =>
        new(TestDefaults.FastOptions());

    /// <summary>
    /// Many concurrent <c>Verify</c> calls against the same stored hash must
    /// all return identical, correct results. The hasher is documented as
    /// thread-safe; this is the regression test that keeps it that way.
    /// </summary>
    [Fact]
    public void Verify_is_safe_under_concurrent_load()
    {
        Argon2idPasswordHasher hasher = NewFastHasher();
        string hash = hasher.HashPassword("correct horse battery staple");
        ConcurrentBag<bool> results = new();

        Parallel.For(0, 64, _ =>
        {
            VerifyResult r = hasher.Verify("correct horse battery staple", hash);
            results.Add(r.Success && !r.NeedsRehash);
        });

        Assert.Equal(64, results.Count);
        Assert.All(results, ok => Assert.True(ok));
    }

    /// <summary>
    /// Concurrent hashes of the same plaintext under the same configuration
    /// produce different stored values (different salts), and each verifies
    /// independently. Proves the salt CSPRNG is contention-free.
    /// </summary>
    [Fact]
    public void HashPassword_produces_distinct_salts_under_concurrent_load()
    {
        Argon2idPasswordHasher hasher = NewFastHasher();
        ConcurrentBag<string> hashes = new();

        Parallel.For(0, 32, _ => hashes.Add(hasher.HashPassword("same-password")));

        Assert.Equal(32, hashes.Distinct(StringComparer.Ordinal).Count());
        Assert.All(hashes, h => Assert.True(hasher.Verify("same-password", h).Success));
    }

    /// <summary>
    /// Verifying with the wrong password under concurrent load must always
    /// return Failed — proves no shared state can be momentarily "matched" by
    /// an interleaving call.
    /// </summary>
    [Fact]
    public void Verify_wrong_password_under_concurrency_is_always_Failed()
    {
        Argon2idPasswordHasher hasher = NewFastHasher();
        string hash = hasher.HashPassword("right");
        ConcurrentBag<VerifyResult> results = new();

        Parallel.For(0, 32, _ => results.Add(hasher.Verify("wrong", hash)));

        Assert.All(results, r => Assert.Equal(VerifyResult.Failed, r));
    }

    /// <summary>
    /// Rehash is requested when ANY single work-factor axis is below current
    /// configuration. Proves the threshold predicate covers every dimension
    /// independently (m, t, p, salt, tag).
    /// </summary>
    [Theory]
    [InlineData("memory")]
    [InlineData("iterations")]
    [InlineData("parallelism")]
    [InlineData("salt")]
    [InlineData("tag")]
    public void Rehash_flagged_when_any_single_axis_is_weaker(string axis)
    {
        // Stored under a baseline "fast" profile that is uniformly weaker than
        // the "stronger" profile below on the axis under test.
        Argon2idOptions weak = TestDefaults.FastOptions();
        Argon2idOptions strong = TestDefaults.FastOptions();

        switch (axis)
        {
            case "memory":
                strong.MemorySizeKib = weak.MemorySizeKib * 2;
                break;
            case "iterations":
                strong.Iterations = weak.Iterations + 1;
                break;
            case "parallelism":
                strong.DegreeOfParallelism = weak.DegreeOfParallelism + 1;
                break;
            case "salt":
                strong.SaltSizeBytes = weak.SaltSizeBytes + 16;
                break;
            case "tag":
                strong.HashSizeBytes = weak.HashSizeBytes + 16;
                break;
        }

        string stored = new Argon2idPasswordHasher(weak).HashPassword("pw");
        VerifyResult r = new Argon2idPasswordHasher(strong).Verify("pw", stored);

        Assert.True(r.Success);
        Assert.True(r.NeedsRehash, $"axis={axis}: expected rehash but did not get one");
    }

    /// <summary>
    /// Adversarial PHC strings must never produce a parsed result. This is the
    /// fail-closed contract that lets <c>Verify</c> safely treat
    /// <see cref="VerifyResult.Failed"/> as "not a match" without a separate
    /// "malformed" code path.
    /// </summary>
    [Theory]
    // Variant prefix attacks.
    [InlineData("$argon2I$v=19$m=8192,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$ARGON2ID$v=19$m=8192,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id $v=19$m=8192,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    // Trailing-garbage attacks.
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$extra")]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ")]
    // Whitespace embedding.
    [InlineData(" $argon2id$v=19$m=8192,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$AA AA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    // Parameter-section attacks.
    [InlineData("$argon2id$v=19$M=8192,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1,x=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$t=1,m=8192,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=-1,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=99999999999,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    // Poisoned work factors: in-int-range but absurd values must die at parse
    // time. Verify spends the declared factors for real, so accepting
    // m=2147483647 would mean a ~2 TiB allocation attempt on every
    // verification of that row — a DoS one poisoned database row could repeat
    // forever. Values below Argon2's own floors would make the underlying
    // implementation throw mid-verify instead of failing closed.
    [InlineData("$argon2id$v=19$m=2147483647,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=8192,t=2147483647,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=2147483647$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=0,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=8192,t=0,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=0$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=16,t=1,p=4$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // violates m ≥ 8·p
    // Version attacks (v=10 is the older Argon2 1.0 spec, not supported here).
    [InlineData("$argon2id$v=10$m=8192,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$$m=8192,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=$m=8192,t=1,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    // Segment-count attacks.
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$AAAA")]                                             // missing hash
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]      // empty salt
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$AAAAAAAAAAAAAAAA$")]                                 // empty hash
    // Base64 attacks: PHC uses unpadded base64, so '=' inside a segment is malformed.
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$AAAA=$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$!!!!$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$AAAA AAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    // Path-traversal-style noise (must never parse).
    [InlineData("$argon2id$..%2F$..%2F$..%2F$..%2F$..%2F")]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$\x00$\x00")]
    // Outright junk.
    [InlineData("argon2id")]
    [InlineData("$")]
    [InlineData("$$$$$")]
    [InlineData("$argon2id$")]
    public void TryParse_fails_closed_on_adversarial_input(string adversarial)
    {
        Argon2idPasswordHasher hasher = NewFastHasher();
        // Both PhcString.TryParse and the higher-level Verify must reject it.
        Assert.False(PhcString.TryParse(adversarial, out PhcString? parsed));
        Assert.Null(parsed);
        Assert.Equal(VerifyResult.Failed, hasher.Verify("anything", adversarial));
    }
}
