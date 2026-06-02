#if NET10_0_OR_GREATER
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using PostQuantum.Jwt;

namespace PostQuantum.Identity.Tokens;

/// <summary>
/// Default <see cref="IPostQuantumTokenService{TUser}"/> implementation. Reads the
/// subject's identity, roles, and claims through <see cref="UserManager{TUser}"/>
/// and issues a PostQuantum.Jwt hybrid token via <see cref="PqJwtBuilder"/>.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
public sealed class PostQuantumTokenService<TUser> : IPostQuantumTokenService<TUser>
    where TUser : class
{
    // Registered claim names PqJwtBuilder manages directly; user-defined claims
    // are not allowed to overwrite them.
    private static readonly HashSet<string> ReservedClaims =
        new(StringComparer.Ordinal) { "iss", "sub", "aud", "exp", "nbf", "iat", "jti" };

    private readonly UserManager<TUser> _userManager;
    private readonly PostQuantumTokenOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates the token service.</summary>
    /// <param name="userManager">The Identity user manager used to read subject data.</param>
    /// <param name="options">The token-issuance options.</param>
    /// <param name="timeProvider">
    /// Clock used for <c>iat</c>/<c>exp</c>. Defaults to
    /// <see cref="TimeProvider.System"/> when null; inject a fake clock in tests.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="userManager"/> or <paramref name="options"/> is null.</exception>
    /// <exception cref="InvalidOperationException">The options are incomplete or invalid.</exception>
    public PostQuantumTokenService(
        UserManager<TUser> userManager,
        IOptions<PostQuantumTokenOptions> options,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(userManager);
        ArgumentNullException.ThrowIfNull(options);
        _userManager = userManager;
        _options = options.Value;
        _options.Validate();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<string> CreateTokenAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        // Source-generated JSON metadata keeps claim serialization reflection-free
        // (trim/AOT-friendly) — see PostQuantumIdentityJsonContext.
        var json = PostQuantumIdentityJsonContext.Default;

        // SigningKey is guaranteed non-null by Validate() in the constructor.
        var builder = new PqJwtBuilder(_timeProvider)
            .WithIssuer(_options.Issuer)
            .WithAudience(_options.Audience)
            .WithSubject(await _userManager.GetUserIdAsync(user).ConfigureAwait(false))
            .WithJwtId(Guid.NewGuid().ToString("N"))
            .WithLifetime(_options.Lifetime);

        string? userName = await _userManager.GetUserNameAsync(user).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(userName))
        {
            builder.WithClaim("name", userName, json.String);
        }

        if (_userManager.SupportsUserEmail)
        {
            string? email = await _userManager.GetEmailAsync(user).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(email))
            {
                builder.WithClaim("email", email, json.String);
            }
        }

        if (_options.IncludeRoles && _userManager.SupportsUserRole)
        {
            IList<string> roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            if (roles.Count == 1)
            {
                builder.WithClaim(_options.RoleClaimType, roles[0], json.String);
            }
            else if (roles.Count > 1)
            {
                // Array shape when more than one role — the common JWT convention.
                builder.WithClaim(_options.RoleClaimType, [.. roles], json.StringArray);
            }
        }

        if (_options.IncludeUserClaims && _userManager.SupportsUserClaim)
        {
            IList<Claim> claims = await _userManager.GetClaimsAsync(user).ConfigureAwait(false);
            foreach (Claim claim in claims)
            {
                if (!ReservedClaims.Contains(claim.Type) && claim.Type != _options.RoleClaimType)
                {
                    builder.WithClaim(claim.Type, claim.Value, json.String);
                }
            }
        }

        if (!string.IsNullOrEmpty(_options.KeyId))
        {
            builder.WithKeyId(_options.KeyId);
        }

        builder.SignWith(_options.SigningKey!);

        if (_options.EncryptForRecipient is not null)
        {
            builder.EncryptFor(_options.EncryptForRecipient);
        }

        return builder.Build();
    }
}
#endif
