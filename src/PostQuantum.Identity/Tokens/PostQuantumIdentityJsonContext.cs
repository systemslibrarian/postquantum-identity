#if NET10_0_OR_GREATER
using System.Text.Json.Serialization;

namespace PostQuantum.Identity.Tokens;

/// <summary>
/// Source-generated JSON metadata for the claim value types emitted by
/// <see cref="PostQuantumTokenService{TUser}"/>. Using these
/// <c>JsonTypeInfo&lt;T&gt;</c> instances with PostQuantum.Jwt's typed
/// <c>WithClaim&lt;T&gt;</c> overload keeps token issuance free of reflection-based
/// serialization, so it is trim- and AOT-friendly.
/// </summary>
[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Serialization)]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(string[]))]
internal sealed partial class PostQuantumIdentityJsonContext : JsonSerializerContext
{
}
#endif
