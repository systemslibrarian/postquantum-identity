using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PostQuantum.Identity.Tokens;

namespace PostQuantum.Identity.Mvc.Demo.Controllers;

/// <summary>
/// Account-management endpoints: register, login, refresh, logout. The same
/// production-shape flows as the minimal-API demo, expressed with attribute
/// routing.
/// </summary>
[ApiController]
[Route("account")]
public sealed class AccountController(
    UserManager<IdentityUser> users,
    IPostQuantumTokenService<IdentityUser>? tokens,
    ConcurrentDictionary<string, DateTimeOffset> revokedJtis) : ControllerBase
{
    /// <summary>Login / registration request body.</summary>
    public sealed record Credentials(string Username, string Password);

    /// <summary>Hashes the password with Argon2id (PHC) and persists the user.</summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] Credentials creds)
    {
        if (creds is null || string.IsNullOrWhiteSpace(creds.Username) || string.IsNullOrWhiteSpace(creds.Password))
        {
            return Problem(title: "Username and password are required.", statusCode: StatusCodes.Status400BadRequest);
        }

        var user = new IdentityUser { UserName = creds.Username };
        IdentityResult result = await users.CreateAsync(user, creds.Password);
        if (result.Succeeded)
        {
            return Ok(new { message = "registered", user.Id });
        }

        return ValidationProblem(new ValidationProblemDetails(
            result.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray())));
    }

    /// <summary>
    /// Verifies the password (Argon2id, fail-closed) and issues a fresh PQ-JWT.
    /// Identical 401 response for "no such user" and "wrong password" so the
    /// endpoint doesn't leak account enumeration.
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] Credentials creds)
    {
        if (creds is null || string.IsNullOrWhiteSpace(creds.Username) || string.IsNullOrWhiteSpace(creds.Password))
        {
            return Problem(title: "Username and password are required.", statusCode: StatusCodes.Status400BadRequest);
        }

        IdentityUser? user = await users.FindByNameAsync(creds.Username);
        if (user is null || !await users.CheckPasswordAsync(user, creds.Password))
        {
            return Unauthorized();
        }

        if (tokens is null)
        {
            return Problem(
                title: "Post-quantum token issuance unavailable (ML-DSA needs OpenSSL 3.5+).",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        string token = await tokens.CreateTokenAsync(user);
        return Ok(new { token, token_type = "PQ-JWT", alg = "ML-DSA-65", kid = TokenConstants.CurrentKeyId });
    }

    /// <summary>
    /// Issues a new token for the current authenticated subject and revokes the
    /// old <c>jti</c>. The standard "rotate before expiry" pattern — a stolen
    /// near-expiry token cannot outlive its replacement.
    /// </summary>
    [Authorize]
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        if (tokens is null)
        {
            return Problem(
                title: "Post-quantum token issuance unavailable.",
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        string? subject = User.FindFirst("sub")?.Value;
        IdentityUser? user = subject is null ? null : await users.FindByIdAsync(subject);
        if (user is null)
        {
            return Unauthorized();
        }

        // Issue the new token BEFORE revoking the old jti. If issuance throws,
        // the caller still has a working bearer token until natural expiry.
        string newToken = await tokens.CreateTokenAsync(user);

        string? oldJti = User.FindFirst("jti")?.Value;
        if (oldJti is not null)
        {
            revokedJtis[oldJti] = DateTimeOffset.UtcNow;
        }

        return Ok(new
        {
            token = newToken,
            token_type = "PQ-JWT",
            alg = "ML-DSA-65",
            kid = TokenConstants.CurrentKeyId,
            rotated_from = oldJti,
        });
    }

    /// <summary>
    /// Adds the current token's <c>jti</c> to the revocation list so it cannot
    /// be used again before natural expiry. Idempotent — repeated calls succeed.
    /// </summary>
    [Authorize]
    [HttpPost("logout")]
    public IActionResult Logout()
    {
        string? jti = User.FindFirst("jti")?.Value;
        if (jti is not null)
        {
            revokedJtis[jti] = DateTimeOffset.UtcNow;
        }

        return Ok(new { message = "logged out", revoked_jti = jti });
    }
}
