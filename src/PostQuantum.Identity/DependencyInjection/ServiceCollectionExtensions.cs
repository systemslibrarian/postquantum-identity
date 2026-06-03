using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
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

        // Startup validation: a misconfigured work factor fails when the host
        // starts, not on the first sign-in. The validator is idempotent; if
        // registered twice it just runs twice.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<Argon2idOptions>, Argon2idOptionsValidator>());

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
    /// One-line opinionated registration: applies a named work-factor preset
    /// from <see cref="Argon2idOptions"/> (<see cref="Argon2idOptions.RecommendedDefault"/>,
    /// <see cref="Argon2idOptions.OwaspMinimum"/>, <see cref="Argon2idOptions.HighSecurity"/>,
    /// <see cref="Argon2idOptions.LowMemoryContainer"/>) without an inline lambda.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="preset">
    /// A preset instance (typically from one of <see cref="Argon2idOptions"/>'s
    /// factory methods). Its values are copied; later mutation of the supplied
    /// instance does not affect the registered hasher.
    /// </param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddIdentityCore&lt;IdentityUser&gt;()
    ///     .Services
    ///     .AddArgon2idPasswordHasher&lt;IdentityUser&gt;(Argon2idOptions.HighSecurity());
    /// </code>
    /// </example>
    public static IServiceCollection AddArgon2idPasswordHasher<TUser>(
        this IServiceCollection services,
        Argon2idOptions preset)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(preset);
        // Snapshot the preset values at registration time. If we deferred this
        // into the Configure lambda, a caller mutating their preset instance
        // before DI is built would silently change what the hasher uses.
        int memory = preset.MemorySizeKib;
        int iterations = preset.Iterations;
        int parallelism = preset.DegreeOfParallelism;
        int saltSize = preset.SaltSizeBytes;
        int hashSize = preset.HashSizeBytes;
        return services.AddArgon2idPasswordHasher<TUser>(o =>
        {
            o.MemorySizeKib = memory;
            o.Iterations = iterations;
            o.DegreeOfParallelism = parallelism;
            o.SaltSizeBytes = saltSize;
            o.HashSizeBytes = hashSize;
        });
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

    /// <summary>
    /// One-line opinionated migrating-hasher registration: applies a named
    /// work-factor preset from <see cref="Argon2idOptions"/>.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="preset">A preset instance (typically from one of <see cref="Argon2idOptions"/>'s factory methods).</param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    public static IServiceCollection AddArgon2idPasswordHasherWithMigration<TUser>(
        this IServiceCollection services,
        Argon2idOptions preset)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(preset);
        // Same snapshot rationale as the non-migrating preset overload above.
        int memory = preset.MemorySizeKib;
        int iterations = preset.Iterations;
        int parallelism = preset.DegreeOfParallelism;
        int saltSize = preset.SaltSizeBytes;
        int hashSize = preset.HashSizeBytes;
        return services.AddArgon2idPasswordHasherWithMigration<TUser>(o =>
        {
            o.MemorySizeKib = memory;
            o.Iterations = iterations;
            o.DegreeOfParallelism = parallelism;
            o.SaltSizeBytes = saltSize;
            o.HashSizeBytes = hashSize;
        });
    }

    /// <summary>
    /// Opt-in startup diagnostic: writes a single structured INFO log line
    /// summarizing the resolved Argon2id configuration when the host starts.
    /// Lets ops confirm at boot exactly what work factors got picked up — useful
    /// where a misconfigured environment variable or a forgotten options-binding
    /// call would otherwise only surface as a latency surprise in production.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    /// <remarks>
    /// Never logs key material, plaintext passwords, or token contents. Uses
    /// <see cref="IHostedService"/> so any host (Web, Worker, generic) that
    /// runs to completion picks it up.
    /// </remarks>
    public static IServiceCollection AddPostQuantumPreflightLogging(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, PostQuantumPreflightLogger>());
        return services;
    }
}

/// <summary>
/// Startup-time validator for <see cref="Argon2idOptions"/>. Surfaces a
/// misconfiguration when the host starts, not on the first hash attempt — so
/// production deployments fail fast and visibly rather than blowing up the
/// first time a user signs in.
/// </summary>
internal sealed class Argon2idOptionsValidator : IValidateOptions<Argon2idOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, Argon2idOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        try
        {
            options.Validate();
            return ValidateOptionsResult.Success;
        }
        catch (ArgumentOutOfRangeException ex)
        {
            // Surface the property + offending value in the failure message so
            // ops can fix the configuration without poking at a stack trace.
            return ValidateOptionsResult.Fail(
                $"Argon2idOptions misconfigured: {ex.ParamName} = {ex.ActualValue}. {ex.Message}");
        }
    }
}
