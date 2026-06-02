namespace PostQuantum.Identity;

/// <summary>
/// The outcome of verifying a password against a stored Argon2id PHC hash.
/// </summary>
/// <remarks>
/// A single <see cref="Argon2idPasswordHasher.Verify(string, string)"/> call
/// reports both whether the password matched and whether the stored hash was
/// produced with weaker parameters than the current configuration, so callers
/// can transparently upgrade ("rehash") on the next successful login from one
/// PHC parse and one Argon2 computation.
/// </remarks>
public readonly record struct VerifyResult
{
    /// <summary>Whether the supplied password matched the stored hash.</summary>
    public bool Success { get; }

    /// <summary>
    /// Whether the stored hash should be recomputed with the current parameters.
    /// Always <see langword="false"/> when <see cref="Success"/> is
    /// <see langword="false"/>.
    /// </summary>
    public bool NeedsRehash { get; }

    private VerifyResult(bool success, bool needsRehash)
    {
        Success = success;
        NeedsRehash = needsRehash;
    }

    /// <summary>A failed verification. <see cref="NeedsRehash"/> is always false.</summary>
    public static VerifyResult Failed { get; } = new(success: false, needsRehash: false);

    /// <summary>A successful verification that does not need a rehash.</summary>
    public static VerifyResult Ok { get; } = new(success: true, needsRehash: false);

    /// <summary>A successful verification whose stored hash should be upgraded.</summary>
    public static VerifyResult OkRehashNeeded { get; } = new(success: true, needsRehash: true);
}
