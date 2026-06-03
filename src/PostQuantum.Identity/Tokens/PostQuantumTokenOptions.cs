#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using PostQuantum.Jwt.Cryptography;

namespace PostQuantum.Identity.Tokens;

/// <summary>
/// Configuration for issuing post-quantum hybrid JWTs to authenticated Identity
/// users via <see cref="PostQuantumTokenService{TUser}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Tokens are always signed with ML-DSA-65 (FIPS 204). When
/// <see cref="EncryptForRecipient"/> is set, the signed token is additionally
/// encrypted with X-Wing (X25519 + ML-KEM-768) + AES-256-GCM
/// ("sign-then-encrypt").
/// </para>
/// <para>
/// Key management is the caller's responsibility: you own the
/// <see cref="SigningKey"/> and any recipient encryption key, including their
/// generation, storage, and rotation. This library never persists key material.
/// </para>
/// <para>
/// <b>Algorithm identifiers and IETF JOSE PQC alignment.</b> The wire-level
/// <c>alg</c>/<c>enc</c> identifiers (<c>ML-DSA-65</c>, <c>X-Wing</c>,
/// <c>A256GCM</c>) are stamped into the JOSE header by the upstream
/// <see href="https://github.com/systemslibrarian/postquantum-jwt">PostQuantum.Jwt</see>
/// builder — this package consumes them, it does not choose them. They are
/// intentionally non-IANA today: the IETF JOSE drafts for post-quantum JWS
/// algorithms (<c>draft-ietf-jose-pq-jose-extensions</c> and friends) have
/// not yet settled on final identifiers, and shipping a placeholder name
/// would invite later interoperability breakage. When the drafts reach RFC
/// or stable WG consensus, PostQuantum.Jwt will adopt the standardized
/// identifiers and this package will pick them up via a normal version bump
/// — no PostQuantum.Identity API change required. Until then, treat these
/// tokens as interoperable only within an ecosystem you fully own. See the
/// <see href="https://github.com/systemslibrarian/postquantum-identity#roadmap-to-10">Roadmap to 1.0</see>.
/// </para>
/// </remarks>
public sealed class PostQuantumTokenOptions
{
    /// <summary>
    /// The ML-DSA-65 private key used to sign issued tokens. Required.
    /// </summary>
    /// <remarks>
    /// Must be an <see cref="MLDsaAlgorithm.MLDsa65"/> key; PostQuantum.Jwt rejects
    /// any other algorithm at build time. The instance is owned by the caller and
    /// is not disposed by the token service.
    /// </remarks>
    public MLDsa? SigningKey { get; set; }

    /// <summary>
    /// Optional <c>kid</c> (key ID) header written into the signature, letting a
    /// verifier select the right public key during rotation.
    /// </summary>
    public string? KeyId { get; set; }

    /// <summary>The <c>iss</c> (issuer) claim. Required (non-empty).</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>The <c>aud</c> (audience) claim. Required (non-empty).</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>How long issued tokens remain valid. Default: 1 hour.</summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// When set, issued tokens are encrypted to this X-Wing public key in addition
    /// to being signed. Leave <see langword="null"/> for signed-only tokens.
    /// </summary>
    public XWingPublicKey? EncryptForRecipient { get; set; }

    /// <summary>
    /// Whether to include the user's roles (from
    /// <see cref="Microsoft.AspNetCore.Identity.UserManager{TUser}.GetRolesAsync"/>)
    /// as the <see cref="RoleClaimType"/> claim. Default: <see langword="true"/>.
    /// </summary>
    public bool IncludeRoles { get; set; } = true;

    /// <summary>
    /// Whether to include the user's persisted claims (from
    /// <see cref="Microsoft.AspNetCore.Identity.UserManager{TUser}.GetClaimsAsync"/>).
    /// Default: <see langword="true"/>.
    /// </summary>
    public bool IncludeUserClaims { get; set; } = true;

    /// <summary>The claim type used for roles. Default: <c>role</c>.</summary>
    public string RoleClaimType { get; set; } = "role";

    /// <summary>
    /// Validates that the required fields are present and coherent.
    /// </summary>
    /// <exception cref="InvalidOperationException">A required field is missing or invalid.</exception>
    public void Validate()
    {
        if (SigningKey is null)
        {
            throw new InvalidOperationException(
                $"{nameof(PostQuantumTokenOptions)}.{nameof(SigningKey)} is required. "
                + "Provide an ML-DSA-65 private key to sign issued tokens.");
        }

        if (string.IsNullOrWhiteSpace(Issuer))
        {
            throw new InvalidOperationException(
                $"{nameof(PostQuantumTokenOptions)}.{nameof(Issuer)} is required (non-empty).");
        }

        if (string.IsNullOrWhiteSpace(Audience))
        {
            throw new InvalidOperationException(
                $"{nameof(PostQuantumTokenOptions)}.{nameof(Audience)} is required (non-empty).");
        }

        if (Lifetime <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"{nameof(PostQuantumTokenOptions)}.{nameof(Lifetime)} must be positive.");
        }

        if (string.IsNullOrWhiteSpace(RoleClaimType))
        {
            throw new InvalidOperationException(
                $"{nameof(PostQuantumTokenOptions)}.{nameof(RoleClaimType)} must be non-empty.");
        }
    }
}
#endif
