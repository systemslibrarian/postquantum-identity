using BenchmarkDotNet.Attributes;
using PostQuantum.Identity;

namespace PostQuantum.Identity.Benchmarks;

/// <summary>
/// Measures the per-call cost of Argon2id hashing and verification across a range
/// of work-factor profiles. Use this to choose memory/iteration settings that hit
/// your target latency budget under concurrent login load on real hardware —
/// the right work factor is the highest one your latency SLO tolerates.
/// </summary>
[MemoryDiagnoser]
[MarkdownExporterAttribute.GitHub]
public class Argon2idBenchmarks
{
    private const string Password = "correct horse battery staple";

    private Argon2idPasswordHasher _hasher = null!;
    private string _storedHash = null!;

    /// <summary>The work-factor profile under test (memory KiB / iterations).</summary>
    [Params("owasp-min:19456:2", "balanced:65536:3", "hardened:131072:4")]
    public string Profile { get; set; } = "balanced:65536:3";

    [GlobalSetup]
    public void Setup()
    {
        string[] parts = Profile.Split(':');
        var options = new Argon2idOptions
        {
            MemorySizeKib = int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture),
            Iterations = int.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture),
        };
        _hasher = new Argon2idPasswordHasher(options);
        _storedHash = _hasher.HashPassword(Password);
    }

    /// <summary>Cost of hashing a new password (registration / password change).</summary>
    [Benchmark]
    public string HashPassword() => _hasher.HashPassword(Password);

    /// <summary>Cost of verifying a correct password (the hot sign-in path).</summary>
    [Benchmark]
    public VerifyResult VerifyCorrect() => _hasher.Verify(Password, _storedHash);

    /// <summary>Cost of rejecting a wrong password (must be the same as a correct one).</summary>
    [Benchmark]
    public VerifyResult VerifyWrong() => _hasher.Verify("not the password", _storedHash);
}
