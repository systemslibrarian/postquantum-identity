namespace PostQuantum.Identity;

/// <summary>
/// Tunable Argon2id work-factor parameters used when hashing passwords.
/// </summary>
/// <remarks>
/// <para>
/// The defaults are opinionated and chosen to be safe for typical 2026 server
/// hardware while leaving headroom for concurrent logins. They comfortably
/// exceed the OWASP minimum (Argon2id, 19&#160;MiB, t=2, p=1) and follow the
/// RFC&#160;9106 second recommended profile shape.
/// </para>
/// <para>
/// Every hash produced by this library stores its own parameters inside the
/// resulting PHC string, so changing these values never breaks verification of
/// existing hashes. Use <see cref="Argon2idPasswordHasher.NeedsRehash(string)"/>
/// (or the <see cref="Microsoft.AspNetCore.Identity.PasswordVerificationResult.SuccessRehashNeeded"/>
/// signal from the Identity adapter) to transparently upgrade older hashes on
/// the next successful login.
/// </para>
/// <para>
/// Properties are settable to support the standard .NET Options pattern
/// (<c>IOptions&lt;TOptions&gt;</c>) and binding from <c>IConfiguration</c>.
/// Hashers treat their options as effectively immutable once constructed &#8212;
/// do not mutate an <see cref="Argon2idOptions"/> instance after passing it to a
/// hasher.
/// </para>
/// </remarks>
public sealed record Argon2idOptions
{
    /// <summary>
    /// Memory cost in kibibytes (KiB). Default: 65536 KiB (64&#160;MiB).
    /// Memory hardness is Argon2's primary defense against GPU/ASIC cracking.
    /// </summary>
    public int MemorySizeKib { get; set; } = 65536;

    /// <summary>
    /// Time cost: the number of passes over memory. Default: 3.
    /// </summary>
    public int Iterations { get; set; } = 3;

    /// <summary>
    /// Degree of parallelism (number of lanes / threads). Default: 1.
    /// Kept low so per-hash CPU cost is predictable under concurrent load.
    /// </summary>
    public int DegreeOfParallelism { get; set; } = 1;

    /// <summary>
    /// Salt length in bytes. Default: 16 (128 bits), the RFC&#160;9106 recommendation.
    /// </summary>
    public int SaltSizeBytes { get; set; } = 16;

    /// <summary>
    /// Derived hash (tag) length in bytes. Default: 32 (256 bits).
    /// </summary>
    public int HashSizeBytes { get; set; } = 32;

    /// <summary>
    /// The library's recommended defaults. Equivalent to <c>new Argon2idOptions()</c>.
    /// </summary>
    /// <remarks>
    /// This is a <em>shared</em> instance for the AppDomain — do not mutate it, or
    /// every later caller picks up your change. Prefer one of the factory methods
    /// (<see cref="RecommendedDefault"/>, <see cref="OwaspMinimum"/>,
    /// <see cref="HighSecurity"/>, <see cref="LowMemoryContainer"/>) when you want
    /// a private, mutable instance.
    /// </remarks>
    public static Argon2idOptions Recommended { get; } = new();

    /// <summary>
    /// Returns a fresh instance of the library's recommended defaults
    /// (64 MiB, t=3, p=1, 16-byte salt, 32-byte tag). Equivalent in values to
    /// <see cref="Recommended"/>, but mutable and not shared.
    /// </summary>
    /// <remarks>
    /// Follows the RFC 9106 second recommended profile shape and exceeds the
    /// OWASP minimum. Right default for most server workloads.
    /// </remarks>
    public static Argon2idOptions RecommendedDefault() => new();

    /// <summary>
    /// Returns the OWASP 2024 minimum Argon2id profile: 19 MiB (<c>m=19456</c>),
    /// <c>t=2</c>, <c>p=1</c>, 16-byte salt, 32-byte tag.
    /// </summary>
    /// <remarks>
    /// Use for very-latency-sensitive endpoints or modest hardware where the
    /// recommended default is too expensive. Above this minimum, raise either
    /// memory or iterations — preferably memory.
    /// </remarks>
    public static Argon2idOptions OwaspMinimum() => new()
    {
        MemorySizeKib = 19456,
        Iterations = 2,
        DegreeOfParallelism = 1,
        SaltSizeBytes = 16,
        HashSizeBytes = 32,
    };

    /// <summary>
    /// Returns a stronger, latency-tolerant profile: 128 MiB (<c>m=131072</c>),
    /// <c>t=4</c>, <c>p=1</c>, 16-byte salt, 32-byte tag.
    /// </summary>
    /// <remarks>
    /// Right pick for admin consoles, key-derivation paths, or any endpoint
    /// where users are happy to wait an extra fraction of a second for stronger
    /// offline-cracking resistance.
    /// </remarks>
    public static Argon2idOptions HighSecurity() => new()
    {
        MemorySizeKib = 131072,
        Iterations = 4,
        DegreeOfParallelism = 1,
        SaltSizeBytes = 16,
        HashSizeBytes = 32,
    };

    /// <summary>
    /// Returns a memory-constrained-container profile: 16 MiB (<c>m=16384</c>),
    /// <c>t=4</c>, <c>p=1</c>, 16-byte salt, 32-byte tag — trades memory for
    /// iterations to stay above the OWASP minimum on tightly-budgeted hosts.
    /// </summary>
    /// <remarks>
    /// Designed for small Kubernetes pods or burstable VMs where the
    /// recommended 64 MiB doesn't fit alongside the rest of the process. Stays
    /// memory-hard, just shifts the cost into the time factor.
    /// </remarks>
    public static Argon2idOptions LowMemoryContainer() => new()
    {
        MemorySizeKib = 16384,
        Iterations = 4,
        DegreeOfParallelism = 1,
        SaltSizeBytes = 16,
        HashSizeBytes = 32,
    };

    /// <summary>
    /// Validates the parameter set, throwing <see cref="ArgumentOutOfRangeException"/>
    /// for any value outside the safe operating range.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// A work factor is outside its documented range.
    /// </exception>
    public void Validate()
    {
        // Lower bounds reflect the OWASP / RFC 9106 minimums; below these the
        // configuration would be insecure rather than merely slow. Upper bounds
        // mirror the verifier's PHC acceptance bounds (see Internal.PhcString) so
        // this library can never emit a hash its own Verify would refuse.
        if (MemorySizeKib < 8192 || MemorySizeKib > Internal.PhcString.MaxMemorySizeKib)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MemorySizeKib), MemorySizeKib,
                $"Memory cost must be between 8192 KiB (8 MiB) and {Internal.PhcString.MaxMemorySizeKib} KiB (4 GiB). The library recommends 65536 KiB (64 MiB).");
        }

        if (Iterations < 1 || Iterations > Internal.PhcString.MaxIterations)
        {
            throw new ArgumentOutOfRangeException(
                nameof(Iterations), Iterations,
                $"Iterations (time cost) must be between 1 and {Internal.PhcString.MaxIterations}.");
        }

        if (DegreeOfParallelism < 1 || DegreeOfParallelism > Internal.PhcString.MaxDegreeOfParallelism)
        {
            throw new ArgumentOutOfRangeException(
                nameof(DegreeOfParallelism), DegreeOfParallelism,
                $"Degree of parallelism must be between 1 and {Internal.PhcString.MaxDegreeOfParallelism}.");
        }

        if (SaltSizeBytes < 16 || SaltSizeBytes > Internal.PhcString.MaxSaltSizeBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(SaltSizeBytes), SaltSizeBytes,
                $"Salt must be between 16 bytes (128 bits) and {Internal.PhcString.MaxSaltSizeBytes} bytes.");
        }

        if (HashSizeBytes < 16 || HashSizeBytes > Internal.PhcString.MaxHashSizeBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(HashSizeBytes), HashSizeBytes,
                $"Hash length must be between 16 bytes (128 bits) and {Internal.PhcString.MaxHashSizeBytes} bytes.");
        }
    }
}
