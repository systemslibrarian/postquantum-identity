using Microsoft.AspNetCore.Identity;

namespace PostQuantum.Identity;

/// <summary>
/// An <see cref="IPasswordHasher{TUser}"/> that routes verification to a legacy
/// hasher (typically the stock <see cref="PasswordHasher{TUser}"/> PBKDF2
/// implementation) when the stored hash isn't an Argon2id PHC string, then
/// transparently rehashes successful logins to Argon2id on the way out.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
/// <remarks>
/// <para>
/// Use this when migrating an existing user store — the stored hashes are a mix
/// of Argon2id (recent registrations) and whatever you used before (PBKDF2,
/// bcrypt-via-an-adapter, etc.). New hashes always come out as Argon2id; old
/// hashes verify against the legacy hasher and are flagged as
/// <see cref="PasswordVerificationResult.SuccessRehashNeeded"/> so ASP.NET Core
/// Identity rewrites them with <see cref="HashPassword"/> on the next sign-in.
/// </para>
/// <para>
/// Routing is purely format-based: any stored value starting with
/// <c>$argon2id$</c> goes to the Argon2id path. Everything else — including
/// <see langword="null"/>, empty, and garbage strings — is handed to the legacy
/// hasher, which is expected to fail safely (and is shielded here so it does not
/// throw on malformed input).
/// </para>
/// </remarks>
/// <example>
/// <code>
/// builder.Services
///     .AddIdentityCore&lt;IdentityUser&gt;()
///     .AddArgon2idPasswordHasherWithMigration&lt;IdentityUser&gt;();
/// </code>
/// </example>
public sealed class MigratingPasswordHasher<TUser> : IPasswordHasher<TUser>
    where TUser : class
{
    private readonly Argon2idPasswordHasher<TUser> _argon2id;
    private readonly IPasswordHasher<TUser> _legacy;

    /// <summary>Creates the migrating hasher.</summary>
    /// <param name="argon2id">
    /// The Argon2id hasher used for new hashes and for verifying any stored PHC
    /// strings that begin with <c>$argon2id$</c>.
    /// </param>
    /// <param name="legacy">
    /// The hasher used to verify any stored value that is <i>not</i> an Argon2id
    /// PHC string. A reported <see cref="PasswordVerificationResult.Success"/> or
    /// <see cref="PasswordVerificationResult.SuccessRehashNeeded"/> is collapsed to
    /// <see cref="PasswordVerificationResult.SuccessRehashNeeded"/> so Identity
    /// stores a fresh Argon2id hash.
    /// </param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public MigratingPasswordHasher(Argon2idPasswordHasher<TUser> argon2id, IPasswordHasher<TUser> legacy)
    {
        ArgumentNullException.ThrowIfNull(argon2id);
        ArgumentNullException.ThrowIfNull(legacy);
        _argon2id = argon2id;
        _legacy = legacy;
    }

    /// <inheritdoc />
    public string HashPassword(TUser user, string password) => _argon2id.HashPassword(user, password);

    /// <inheritdoc />
    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        if (Argon2idPasswordHasher.IsArgon2idHash(hashedPassword))
        {
            return _argon2id.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }

        // The stock ASP.NET Core Identity PasswordHasher<TUser> throws on null or
        // non-base64 stored values; the Argon2id side of this library fails safe on
        // garbage. The migrating adapter follows the safe contract so callers don't
        // have to special-case legacy data.
        PasswordVerificationResult legacyResult;
        try
        {
            legacyResult = _legacy.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            return PasswordVerificationResult.Failed;
        }

        // Collapse Success and SuccessRehashNeeded into the same Identity signal so
        // the next sign-in rewrites the stored hash as Argon2id.
        return legacyResult switch
        {
            PasswordVerificationResult.Success
                or PasswordVerificationResult.SuccessRehashNeeded
                => PasswordVerificationResult.SuccessRehashNeeded,
            _ => legacyResult,
        };
    }
}
