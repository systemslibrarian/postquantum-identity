using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using PostQuantum.Identity.Internal;

namespace PostQuantum.Identity;

/// <summary>
/// A secure-by-default Argon2id password hasher that produces and verifies
/// PHC-formatted hashes (<c>$argon2id$v=19$m=...,t=...,p=...$salt$hash</c>).
/// </summary>
/// <remarks>
/// <para>
/// This is the framework-agnostic core. For ASP.NET Core Identity, register the
/// <see cref="Argon2idPasswordHasher{TUser}"/> adapter (it forwards to an
/// instance of this type) via the
/// <see cref="DependencyInjection.IdentityBuilderExtensions"/> helpers.
/// </para>
/// <para>
/// Instances are immutable and thread-safe; create one (typically a singleton)
/// and share it. Every hash embeds its own work factors, so changing the
/// configured <see cref="Argon2idOptions"/> never invalidates previously stored
/// hashes — older hashes verify correctly and report
/// <see cref="VerifyResult.NeedsRehash"/> so callers can upgrade them.
/// </para>
/// </remarks>
public sealed class Argon2idPasswordHasher
{
    private readonly Argon2idOptions _options;

    /// <summary>Creates a hasher with the recommended default work factors.</summary>
    public Argon2idPasswordHasher()
        : this(Argon2idOptions.Recommended)
    {
    }

    /// <summary>Creates a hasher with the given work factors.</summary>
    /// <param name="options">
    /// The Argon2id work factors. A defensive copy is taken, so later mutation of
    /// the supplied instance does not affect this hasher.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A work factor is out of range.</exception>
    public Argon2idPasswordHasher(Argon2idOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        // Defensive copy: callers (and the Options pipeline) may keep mutating
        // the instance they handed us; the hasher must stay stable.
        _options = options with { };
    }

    /// <summary>
    /// Cheap, allocation-free check of whether a stored value is an Argon2id PHC
    /// string produced by this library (it starts with <c>$argon2id$</c>). Used to
    /// route verification in migration scenarios; it does <b>not</b> validate the
    /// full structure (that is <see cref="Verify(string, string)"/>'s job).
    /// </summary>
    /// <param name="hashedPassword">A candidate stored hash, possibly null.</param>
    /// <returns><see langword="true"/> if it begins with the argon2id PHC prefix.</returns>
    public static bool IsArgon2idHash(string? hashedPassword) =>
        hashedPassword is not null
        && hashedPassword.StartsWith("$" + Internal.PhcString.Argon2idId + "$", StringComparison.Ordinal);

    /// <summary>Hashes a password and returns a self-describing PHC string.</summary>
    /// <param name="password">The plaintext password. Must not be null.</param>
    /// <returns>A PHC-formatted Argon2id hash safe to persist.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is null.</exception>
    public string HashPassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        byte[] salt = RandomNumberGenerator.GetBytes(_options.SaltSizeBytes);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            byte[] hash = Compute(passwordBytes, salt, _options.MemorySizeKib, _options.Iterations, _options.DegreeOfParallelism, _options.HashSizeBytes);
            return PhcString.Format(_options, salt, hash);
        }
        finally
        {
            // Don't leave the UTF-8 password bytes lingering on the managed heap.
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <summary>
    /// Verifies a password against a stored PHC hash and, in the same pass,
    /// reports whether the stored hash should be upgraded to the current work
    /// factors.
    /// </summary>
    /// <param name="password">The plaintext password to check.</param>
    /// <param name="hashedPassword">A PHC-formatted hash previously produced by this library.</param>
    /// <returns>
    /// <see cref="VerifyResult.Failed"/> if the input is malformed or the password
    /// does not match; otherwise a successful result whose
    /// <see cref="VerifyResult.NeedsRehash"/> flag indicates a weaker-than-current
    /// stored configuration.
    /// </returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public VerifyResult Verify(string password, string hashedPassword)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(hashedPassword);

        // Fail closed on anything we don't recognize — a malformed stored value
        // is never a match.
        if (!PhcString.TryParse(hashedPassword, out PhcString? parsed) || parsed is null)
        {
            return VerifyResult.Failed;
        }

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            byte[] candidate = Compute(
                passwordBytes,
                parsed.Salt,
                parsed.MemorySizeKib,
                parsed.Iterations,
                parsed.DegreeOfParallelism,
                parsed.Hash.Length);

            bool matches = CryptographicOperations.FixedTimeEquals(candidate, parsed.Hash);
            CryptographicOperations.ZeroMemory(candidate);

            if (!matches)
            {
                return VerifyResult.Failed;
            }

            return IsWeakerThanCurrent(parsed) ? VerifyResult.OkRehashNeeded : VerifyResult.Ok;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <summary>
    /// Reports whether a stored hash was produced with weaker parameters than the
    /// current configuration (and so should be upgraded on next login), without
    /// verifying a password.
    /// </summary>
    /// <param name="hashedPassword">A stored PHC hash.</param>
    /// <returns>
    /// <see langword="true"/> if the value is not a recognizable argon2id PHC
    /// string, or its work factors / tag length are below the current options.
    /// </returns>
    public bool NeedsRehash(string hashedPassword)
    {
        ArgumentNullException.ThrowIfNull(hashedPassword);
        if (!PhcString.TryParse(hashedPassword, out PhcString? parsed) || parsed is null)
        {
            // Unparseable or a different scheme (e.g. legacy PBKDF2): treat as
            // needing an upgrade so the caller re-hashes with Argon2id.
            return true;
        }

        return IsWeakerThanCurrent(parsed);
    }

    private bool IsWeakerThanCurrent(PhcString stored) =>
        stored.MemorySizeKib < _options.MemorySizeKib
        || stored.Iterations < _options.Iterations
        || stored.DegreeOfParallelism < _options.DegreeOfParallelism
        || stored.Hash.Length < _options.HashSizeBytes
        || stored.Salt.Length < _options.SaltSizeBytes;

    private static byte[] Compute(byte[] password, byte[] salt, int memoryKib, int iterations, int parallelism, int hashLength)
    {
        using var argon2 = new Argon2id(password)
        {
            Salt = salt,
            MemorySize = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };
        return argon2.GetBytes(hashLength);
    }
}
