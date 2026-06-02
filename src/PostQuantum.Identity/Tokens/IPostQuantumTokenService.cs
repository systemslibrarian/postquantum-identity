#if NET10_0_OR_GREATER
namespace PostQuantum.Identity.Tokens;

/// <summary>
/// Issues post-quantum hybrid JWTs for authenticated ASP.NET Core Identity users.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
/// <remarks>
/// Available on .NET 10 only: the underlying PostQuantum.Jwt library and the BCL
/// post-quantum primitives (ML-DSA / ML-KEM) ship for .NET 10.
/// </remarks>
public interface IPostQuantumTokenService<in TUser>
    where TUser : class
{
    /// <summary>
    /// Creates a signed (and optionally encrypted) post-quantum hybrid token whose
    /// claims describe <paramref name="user"/>: <c>sub</c> is the Identity user id,
    /// with name, optional email, roles, and persisted user claims added per the
    /// configured <see cref="PostQuantumTokenOptions"/>.
    /// </summary>
    /// <param name="user">The authenticated user the token represents.</param>
    /// <param name="cancellationToken">Cancellation token for the underlying store reads.</param>
    /// <returns>The compact-serialized token string.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="user"/> is null.</exception>
    Task<string> CreateTokenAsync(TUser user, CancellationToken cancellationToken = default);
}
#endif
