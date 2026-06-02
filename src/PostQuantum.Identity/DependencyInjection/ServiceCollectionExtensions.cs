using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace PostQuantum.Identity.DependencyInjection;

/// <summary>
/// Dependency-injection helpers for registering the Argon2id password hasher
/// (and, on .NET 10, the post-quantum token service) with ASP.NET Core Identity.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the secure-by-default Argon2id hasher as the
    /// <see cref="IPasswordHasher{TUser}"/> for ASP.NET Core Identity, optionally
    /// configuring its work factors inline.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type (e.g. <c>IdentityUser</c>).</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">
    /// Optional callback to tune <see cref="Argon2idOptions"/>. When omitted, a
    /// prior <c>services.Configure&lt;Argon2idOptions&gt;(...)</c> wins; failing
    /// that, <see cref="Argon2idOptions.Recommended"/> is used.
    /// </param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddIdentityCore&lt;IdentityUser&gt;()
    ///     .Services
    ///     .AddArgon2idPasswordHasher&lt;IdentityUser&gt;(opts =&gt; opts.MemorySizeKib = 131072);
    /// </code>
    /// </example>
    public static IServiceCollection AddArgon2idPasswordHasher<TUser>(
        this IServiceCollection services,
        Action<Argon2idOptions>? configureOptions = null)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<Argon2idOptions>();
        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }

        // Resolve the core hasher lazily so a later Configure call still wins.
        services.TryAddSingleton(sp =>
        {
            Argon2idOptions opts = sp.GetService<IOptions<Argon2idOptions>>()?.Value
                                   ?? Argon2idOptions.Recommended;
            return new Argon2idPasswordHasher(opts);
        });

        services.Replace(ServiceDescriptor.Singleton<IPasswordHasher<TUser>, Argon2idPasswordHasher<TUser>>());
        return services;
    }

    /// <summary>
    /// Registers a <see cref="MigratingPasswordHasher{TUser}"/> as the
    /// <see cref="IPasswordHasher{TUser}"/>: Argon2id for new hashes, and the stock
    /// ASP.NET Core Identity <see cref="PasswordHasher{TUser}"/> (PBKDF2) to verify
    /// any stored hash that isn't already Argon2id. Successful legacy verifications
    /// report <see cref="PasswordVerificationResult.SuccessRehashNeeded"/>, so
    /// Identity upgrades the stored value to Argon2id on the next sign-in.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">Optional callback to tune <see cref="Argon2idOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    public static IServiceCollection AddArgon2idPasswordHasherWithMigration<TUser>(
        this IServiceCollection services,
        Action<Argon2idOptions>? configureOptions = null)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(services);

        // Reuse the standard registration to wire the core hasher + options, then
        // wrap the Argon2id adapter and the stock PBKDF2 hasher in the migrator.
        services.AddArgon2idPasswordHasher<TUser>(configureOptions);
        services.Replace(ServiceDescriptor.Singleton<IPasswordHasher<TUser>>(sp =>
        {
            var argon2id = new Argon2idPasswordHasher<TUser>(sp.GetRequiredService<Argon2idPasswordHasher>());
            var legacy = new PasswordHasher<TUser>();
            return new MigratingPasswordHasher<TUser>(argon2id, legacy);
        }));
        return services;
    }
}
