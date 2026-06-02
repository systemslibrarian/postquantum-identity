using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace PostQuantum.Identity.Mvc.Demo.Controllers;

/// <summary>
/// A protected endpoint. The <c>PqJwtBearer</c> handler validates the
/// post-quantum token (fail-closed) and populates <see cref="ControllerBase.User"/>
/// before this action runs.
/// </summary>
[ApiController]
[Route("me")]
[Authorize]
public sealed class MeController : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok(new
    {
        subject = User.FindFirst("sub")?.Value,
        name = User.FindFirst("name")?.Value,
        roles = User.FindAll("role").Select(c => c.Value).ToArray(),
    });
}
