using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PostQuantum.Identity.Tokens;

namespace PostQuantum.Identity.Mvc.Demo.Controllers;

/// <summary>Registration and login. Passwords are hashed with Argon2id.</summary>
[ApiController]
[Route("account")]
public sealed class AccountController(
    UserManager<IdentityUser> users,
    IPostQuantumTokenService<IdentityUser>? tokens) : ControllerBase
{
    /// <summary>Login/registration request body.</summary>
    public sealed record Credentials(string Username, string Password);

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] Credentials creds)
    {
        var user = new IdentityUser { UserName = creds.Username };
        IdentityResult result = await users.CreateAsync(user, creds.Password);
        return result.Succeeded
            ? Ok(new { message = "registered", user.Id })
            : BadRequest(new { errors = result.Errors.Select(e => e.Description) });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] Credentials creds)
    {
        IdentityUser? user = await users.FindByNameAsync(creds.Username);
        if (user is null || !await users.CheckPasswordAsync(user, creds.Password))
        {
            // Identical response for "no such user" and "wrong password".
            return Unauthorized();
        }

        if (tokens is null)
        {
            return StatusCode(503, new { error = "Post-quantum token issuance unavailable (ML-DSA needs OpenSSL 3.5+)." });
        }

        string token = await tokens.CreateTokenAsync(user);
        return Ok(new { token, token_type = "PQ-JWT (ML-DSA-65)" });
    }
}
