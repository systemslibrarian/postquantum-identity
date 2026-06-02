#if NET10_0_OR_GREATER
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PostQuantum.Identity.Tokens;

namespace PostQuantum.Identity.DependencyInjection;

/// <summary>
/// Dependency-injection helpers for the post-quantum hybrid-token service.
/// Available on .NET 10 only (PostQuantum.Jwt and the BCL PQC primitives target
/// .NET 10).
/// </summary>
public static class TokenServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IPostQuantumTokenService{TUser}"/> so authenticated
    /// users can be issued post-quantum hybrid JWTs.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">
    /// Callback that configures <see cref="PostQuantumTokenOptions"/> — at minimum
    /// the ML-DSA-65 <see cref="PostQuantumTokenOptions.SigningKey"/>,
    /// <see cref="PostQuantumTokenOptions.Issuer"/>, and
    /// <see cref="PostQuantumTokenOptions.Audience"/>.
    /// </param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public static IServiceCollection AddPostQuantumTokenService<TUser>(
        this IServiceCollection services,
        Action<PostQuantumTokenOptions> configureOptions)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.AddOptions<PostQuantumTokenOptions>().Configure(configureOptions);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped<IPostQuantumTokenService<TUser>, PostQuantumTokenService<TUser>>();
        return services;
    }

    /// <summary>
    /// Identity-builder counterpart to
    /// <see cref="AddPostQuantumTokenService{TUser}(IServiceCollection, Action{PostQuantumTokenOptions})"/>,
    /// so token issuance can be added inline in the Identity builder chain.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type. Must match the builder's user type.</typeparam>
    /// <param name="builder">The Identity builder being configured.</param>
    /// <param name="configureOptions">Callback that configures <see cref="PostQuantumTokenOptions"/>.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="InvalidOperationException"><typeparamref name="TUser"/> does not match the builder's user type.</exception>
    public static IdentityBuilder AddPostQuantumTokens<TUser>(
        this IdentityBuilder builder,
        Action<PostQuantumTokenOptions> configureOptions)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configureOptions);
        IdentityBuilderExtensions.EnsureUserTypeMatches<TUser>(builder);
        builder.Services.AddPostQuantumTokenService<TUser>(configureOptions);
        return builder;
    }
}
#endif
