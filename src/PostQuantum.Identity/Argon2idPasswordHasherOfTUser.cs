using Microsoft.AspNetCore.Identity;

namespace PostQuantum.Identity;

/// <summary>
/// An <see cref="IPasswordHasher{TUser}"/> implementation backed by the
/// secure-by-default Argon2id <see cref="Argon2idPasswordHasher"/>, suitable for
/// ASP.NET Core Identity.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
/// <remarks>
/// Verification reports <see cref="PasswordVerificationResult.SuccessRehashNeeded"/>
/// when the stored hash was produced with weaker parameters than the current
/// configuration, so ASP.NET Core Identity transparently upgrades it on the next
/// sign-in. The adapter is generic over <typeparamref name="TUser"/> only to
/// satisfy the Identity interface; the user object itself is not part of the
/// hash (Identity salts per-hash, and so do we).
/// </remarks>
public sealed class Argon2idPasswordHasher<TUser> : IPasswordHasher<TUser>
    where TUser : class
{
    private readonly Argon2idPasswordHasher _hasher;

    /// <summary>Creates the adapter around a configured core hasher.</summary>
    /// <param name="hasher">The shared, thread-safe core hasher (typically a singleton).</param>
    /// <exception cref="ArgumentNullException"><paramref name="hasher"/> is null.</exception>
    public Argon2idPasswordHasher(Argon2idPasswordHasher hasher)
    {
        ArgumentNullException.ThrowIfNull(hasher);
        _hasher = hasher;
    }

    /// <inheritdoc />
    public string HashPassword(TUser user, string password) => _hasher.HashPassword(password);

    /// <inheritdoc />
    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        // Verify(...) returns both match-result and rehash-hint from a single
        // PHC parse, so this is one parse + one Argon2 computation per call.
        VerifyResult result = _hasher.Verify(providedPassword, hashedPassword);
        return result switch
        {
            { Success: false } => PasswordVerificationResult.Failed,
            { NeedsRehash: true } => PasswordVerificationResult.SuccessRehashNeeded,
            _ => PasswordVerificationResult.Success,
        };
    }
}
