#if NET10_0_OR_GREATER
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace PostQuantum.Identity.Tests.Tokens;

/// <summary>A user fixture for the token-service tests.</summary>
internal sealed class FakeUser
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string UserName { get; init; } = "ada";
    public string Email { get; init; } = "ada@example.com";
    public List<string> Roles { get; } = [];
    public List<Claim> Claims { get; } = [];
}

/// <summary>
/// Minimal in-memory <see cref="IUserStore{TUser}"/> implementing the read paths
/// the token service uses (id/name/email/roles/claims). Mutators throw — the
/// token service never calls them.
/// </summary>
internal sealed class FakeUserStore :
    IUserStore<FakeUser>,
    IUserEmailStore<FakeUser>,
    IUserRoleStore<FakeUser>,
    IUserClaimStore<FakeUser>
{
    // Reads used by the token service.
    public Task<string> GetUserIdAsync(FakeUser user, CancellationToken ct) => Task.FromResult(user.Id);
    public Task<string?> GetUserNameAsync(FakeUser user, CancellationToken ct) => Task.FromResult<string?>(user.UserName);
    public Task<string?> GetEmailAsync(FakeUser user, CancellationToken ct) => Task.FromResult<string?>(user.Email);
    public Task<IList<string>> GetRolesAsync(FakeUser user, CancellationToken ct) => Task.FromResult<IList<string>>(user.Roles);
    public Task<IList<Claim>> GetClaimsAsync(FakeUser user, CancellationToken ct) => Task.FromResult<IList<Claim>>(user.Claims);

    public void Dispose() { }

    // Everything below is unused by the token service.
    public Task SetUserNameAsync(FakeUser user, string? userName, CancellationToken ct) => throw new NotSupportedException();
    public Task<string?> GetNormalizedUserNameAsync(FakeUser user, CancellationToken ct) => Task.FromResult<string?>(user.UserName.ToUpperInvariant());
    public Task SetNormalizedUserNameAsync(FakeUser user, string? normalizedName, CancellationToken ct) => Task.CompletedTask;
    public Task<IdentityResult> CreateAsync(FakeUser user, CancellationToken ct) => throw new NotSupportedException();
    public Task<IdentityResult> UpdateAsync(FakeUser user, CancellationToken ct) => throw new NotSupportedException();
    public Task<IdentityResult> DeleteAsync(FakeUser user, CancellationToken ct) => throw new NotSupportedException();
    public Task<FakeUser?> FindByIdAsync(string userId, CancellationToken ct) => throw new NotSupportedException();
    public Task<FakeUser?> FindByNameAsync(string normalizedUserName, CancellationToken ct) => throw new NotSupportedException();

    public Task SetEmailAsync(FakeUser user, string? email, CancellationToken ct) => throw new NotSupportedException();
    public Task<bool> GetEmailConfirmedAsync(FakeUser user, CancellationToken ct) => Task.FromResult(true);
    public Task SetEmailConfirmedAsync(FakeUser user, bool confirmed, CancellationToken ct) => Task.CompletedTask;
    public Task<FakeUser?> FindByEmailAsync(string normalizedEmail, CancellationToken ct) => throw new NotSupportedException();
    public Task<string?> GetNormalizedEmailAsync(FakeUser user, CancellationToken ct) => Task.FromResult<string?>(user.Email.ToUpperInvariant());
    public Task SetNormalizedEmailAsync(FakeUser user, string? normalizedEmail, CancellationToken ct) => Task.CompletedTask;

    public Task AddToRoleAsync(FakeUser user, string roleName, CancellationToken ct) => throw new NotSupportedException();
    public Task RemoveFromRoleAsync(FakeUser user, string roleName, CancellationToken ct) => throw new NotSupportedException();
    public Task<bool> IsInRoleAsync(FakeUser user, string roleName, CancellationToken ct) => Task.FromResult(user.Roles.Contains(roleName));
    public Task<IList<FakeUser>> GetUsersInRoleAsync(string roleName, CancellationToken ct) => throw new NotSupportedException();

    public Task AddClaimsAsync(FakeUser user, IEnumerable<Claim> claims, CancellationToken ct) => throw new NotSupportedException();
    public Task ReplaceClaimAsync(FakeUser user, Claim claim, Claim newClaim, CancellationToken ct) => throw new NotSupportedException();
    public Task RemoveClaimsAsync(FakeUser user, IEnumerable<Claim> claims, CancellationToken ct) => throw new NotSupportedException();
    public Task<IList<FakeUser>> GetUsersForClaimAsync(Claim claim, CancellationToken ct) => throw new NotSupportedException();
}
#endif
