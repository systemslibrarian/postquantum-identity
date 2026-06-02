using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace PostQuantum.Identity.DependencyInjection;

/// <summary>
/// Extension methods that wire PostQuantum.Identity into the natural ASP.NET Core
/// Identity builder chain.
/// </summary>
/// <example>
/// <code>
/// builder.Services
///     .AddIdentityCore&lt;IdentityUser&gt;()
///     .AddArgon2idPasswordHasher&lt;IdentityUser&gt;();
/// </code>
/// </example>
public static class IdentityBuilderExtensions
{
    /// <summary>
    /// Registers the Argon2id hasher as the <see cref="IPasswordHasher{TUser}"/>
    /// for <typeparamref name="TUser"/>, optionally tuning its work factors.
    /// </summary>
    /// <typeparam name="TUser">
    /// The Identity user type. Must match the type passed to
    /// <c>AddIdentityCore&lt;TUser&gt;()</c>; a mismatch throws.
    /// </typeparam>
    /// <param name="builder">The Identity builder being configured.</param>
    /// <param name="configureOptions">Optional callback to tune <see cref="Argon2idOptions"/>.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// <typeparamref name="TUser"/> does not match the user type of <paramref name="builder"/>.
    /// </exception>
    public static IdentityBuilder AddArgon2idPasswordHasher<TUser>(
        this IdentityBuilder builder,
        Action<Argon2idOptions>? configureOptions = null)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(builder);
        EnsureUserTypeMatches<TUser>(builder);
        builder.Services.AddArgon2idPasswordHasher<TUser>(configureOptions);
        return builder;
    }

    /// <summary>
    /// Registers a <see cref="MigratingPasswordHasher{TUser}"/>: Argon2id for new
    /// hashes, with the stock ASP.NET Core Identity PBKDF2 hasher verifying (and
    /// triggering re-hash of) any legacy stored hash. The recommended adapter when
    /// migrating an existing user store to Argon2id.
    /// </summary>
    /// <typeparam name="TUser">
    /// The Identity user type. Must match the type passed to
    /// <c>AddIdentityCore&lt;TUser&gt;()</c>; a mismatch throws.
    /// </typeparam>
    /// <param name="builder">The Identity builder being configured.</param>
    /// <param name="configureOptions">Optional callback to tune <see cref="Argon2idOptions"/>.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// <typeparamref name="TUser"/> does not match the user type of <paramref name="builder"/>.
    /// </exception>
    public static IdentityBuilder AddArgon2idPasswordHasherWithMigration<TUser>(
        this IdentityBuilder builder,
        Action<Argon2idOptions>? configureOptions = null)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(builder);
        EnsureUserTypeMatches<TUser>(builder);
        builder.Services.AddArgon2idPasswordHasherWithMigration<TUser>(configureOptions);
        return builder;
    }

    /// <summary>
    /// Defensively reject mismatched user types early so the consumer sees a
    /// helpful error at registration time rather than a confusing
    /// <c>IPasswordHasher&lt;Wrong&gt;</c> resolution failure later.
    /// </summary>
    internal static void EnsureUserTypeMatches<TUser>(IdentityBuilder builder)
    {
        if (builder.UserType != typeof(TUser))
        {
            throw new InvalidOperationException(
                $"AddArgon2idPasswordHasher<{typeof(TUser).Name}> was called on an "
                + $"IdentityBuilder configured for {builder.UserType?.Name ?? "<null>"}. "
                + "These must match — pass the same TUser used in AddIdentityCore<TUser>().");
        }
    }
}
