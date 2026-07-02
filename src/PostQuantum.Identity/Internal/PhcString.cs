using System.Globalization;

namespace PostQuantum.Identity.Internal;

/// <summary>
/// Parses and formats Argon2id hashes in the PHC string format
/// (<c>$argon2id$v=19$m=&lt;mem&gt;,t=&lt;iter&gt;,p=&lt;par&gt;$&lt;salt&gt;$&lt;hash&gt;</c>),
/// the de-facto interop format produced by the reference Argon2 CLI, libsodium,
/// and most modern hashing libraries.
/// </summary>
/// <remarks>
/// <para>
/// Salt and hash are Base64 encoded <b>without</b> padding, per the PHC spec.
/// Parsing is strict and fail-closed: any malformed field yields
/// <see langword="false"/> from <see cref="TryParse"/> rather than a partial
/// result, so a corrupt stored value can never be coaxed into a "match".
/// </para>
/// <para>
/// Parsing also enforces the acceptance bounds below. The parsed work factors
/// are <em>spent for real</em> by <c>Verify</c>, so a poisoned stored row
/// (compromised database, hostile import) must not be able to demand an absurd
/// computation — e.g. <c>m=2147483647</c> would otherwise attempt a ~2 TiB
/// allocation on every verification — nor slip parameters below Argon2's own
/// floors, where the underlying implementation would throw mid-verify instead
/// of failing closed. The bounds are deliberately generous: they clear every
/// profile a legitimate encoder emits (reference CLI, libsodium up to its
/// "sensitive" 1 GiB profile, all of this library's presets) while capping the
/// worst case a hostile row can extract from one call.
/// </para>
/// </remarks>
internal sealed record PhcString
{
    /// <summary>The Argon2 variant identifier. This library only emits/accepts <c>argon2id</c>.</summary>
    public const string Argon2idId = "argon2id";

    /// <summary>The Argon2 version number this library emits (0x13 == 19).</summary>
    public const int Argon2Version13 = 19;

    /// <summary>Smallest accepted memory cost — the RFC 9106 floor for p=1 (8 KiB). This library <em>emits</em> ≥ 8192 KiB; verification accepts spec-legal weaker hashes and flags them for rehash.</summary>
    public const int MinMemorySizeKib = 8;

    /// <summary>Largest accepted memory cost (4 GiB). Above libsodium's strongest published profile; a stored value demanding more is treated as poisoned, not verified.</summary>
    public const int MaxMemorySizeKib = 4 * 1024 * 1024;

    /// <summary>Smallest accepted time cost.</summary>
    public const int MinIterations = 1;

    /// <summary>Largest accepted time cost. No published password-hashing profile approaches this; it exists to bound the CPU a poisoned row can demand.</summary>
    public const int MaxIterations = 512;

    /// <summary>Smallest accepted parallelism.</summary>
    public const int MinDegreeOfParallelism = 1;

    /// <summary>Largest accepted parallelism.</summary>
    public const int MaxDegreeOfParallelism = 64;

    /// <summary>Smallest accepted salt length — the RFC 9106 floor. This library emits ≥ 16.</summary>
    public const int MinSaltSizeBytes = 8;

    /// <summary>Largest accepted salt length.</summary>
    public const int MaxSaltSizeBytes = 64;

    /// <summary>Smallest accepted tag length (96 bits). This library emits ≥ 16 bytes; anything shorter than 12 is not a credible password verifier.</summary>
    public const int MinHashSizeBytes = 12;

    /// <summary>Largest accepted tag length.</summary>
    public const int MaxHashSizeBytes = 512;

    /// <summary>Memory cost in KiB (the <c>m</c> parameter).</summary>
    public required int MemorySizeKib { get; init; }

    /// <summary>Time cost / iterations (the <c>t</c> parameter).</summary>
    public required int Iterations { get; init; }

    /// <summary>Degree of parallelism (the <c>p</c> parameter).</summary>
    public required int DegreeOfParallelism { get; init; }

    /// <summary>The raw salt bytes.</summary>
    public required byte[] Salt { get; init; }

    /// <summary>The raw derived-hash (tag) bytes.</summary>
    public required byte[] Hash { get; init; }

    /// <summary>Formats the components into a PHC string.</summary>
    /// <param name="options">The work factors used to produce the hash.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="hash">The derived hash bytes.</param>
    /// <returns>A PHC-formatted <c>$argon2id$...</c> string.</returns>
    public static string Format(Argon2idOptions options, byte[] salt, byte[] hash)
    {
        // Culture-invariant integer formatting so the wire format never depends
        // on the host locale.
        return string.Create(CultureInfo.InvariantCulture,
            $"${Argon2idId}$v={Argon2Version13}$m={options.MemorySizeKib},t={options.Iterations},p={options.DegreeOfParallelism}${EncodeNoPad(salt)}${EncodeNoPad(hash)}");
    }

    /// <summary>
    /// Attempts to parse a PHC string produced by this library (or any
    /// spec-compliant Argon2id encoder).
    /// </summary>
    /// <param name="value">The candidate PHC string.</param>
    /// <param name="result">The parsed components on success; otherwise null.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is a well-formed argon2id PHC string.</returns>
    public static bool TryParse(string? value, out PhcString? result)
    {
        result = null;
        if (string.IsNullOrEmpty(value) || value[0] != '$')
        {
            return false;
        }

        // Leading '$' produces an empty first segment; expect exactly:
        // ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
        string[] parts = value.Split('$');
        if (parts.Length != 6 || parts[1] != Argon2idId)
        {
            return false;
        }

        if (!TryParseTagged(parts[2], "v", out int version) || version != Argon2Version13)
        {
            return false;
        }

        string[] costs = parts[3].Split(',');
        if (costs.Length != 3
            || !TryParseTagged(costs[0], "m", out int memory)
            || !TryParseTagged(costs[1], "t", out int iterations)
            || !TryParseTagged(costs[2], "p", out int parallelism))
        {
            return false;
        }

        // Acceptance bounds — see the type remarks. The parsed factors drive a
        // real Argon2id computation, so an out-of-range value is rejected here
        // (fail-closed) rather than allocated/thrown on in Verify. The final
        // check is Argon2's own structural requirement m ≥ 8·p (RFC 9106 §3.1).
        if (memory is < MinMemorySizeKib or > MaxMemorySizeKib
            || iterations is < MinIterations or > MaxIterations
            || parallelism is < MinDegreeOfParallelism or > MaxDegreeOfParallelism
            || memory < 8 * parallelism)
        {
            return false;
        }

        if (!TryDecodeNoPad(parts[4], out byte[]? salt)
            || !TryDecodeNoPad(parts[5], out byte[]? hash)
            || salt.Length is < MinSaltSizeBytes or > MaxSaltSizeBytes
            || hash.Length is < MinHashSizeBytes or > MaxHashSizeBytes)
        {
            return false;
        }

        result = new PhcString
        {
            MemorySizeKib = memory,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
            Salt = salt,
            Hash = hash,
        };
        return true;
    }

    private static bool TryParseTagged(string segment, string tag, out int value)
    {
        value = 0;
        // Expect "<tag>=<int>" with the exact tag and a non-negative integer.
        if (!segment.StartsWith(tag + "=", StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> digits = segment.AsSpan(tag.Length + 1);

        // Numeric canonicality: NumberStyles.None still accepts leading zeros,
        // so "m=08192" would alias to "m=8192" — a distinct stored string with
        // identical parsed components, breaching the one-accepted-encoding-per-
        // hash pin the salt/tag segments already enforce. Reject the alias.
        if (digits.Length > 1 && digits[0] == '0')
        {
            return false;
        }

        return int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    private static string EncodeNoPad(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=');

    // The longest base64 field we could ever accept: a MaxHashSizeBytes tag,
    // re-padded. Rejecting on length FIRST keeps the decode work bounded — a
    // multi-megabyte poisoned field must not be padded, decoded, and re-encoded
    // in full before the byte-length bounds finally turn it away.
    private const int MaxBase64FieldChars = (MaxHashSizeBytes + 2) / 3 * 4;

    private static bool TryDecodeNoPad(string value, out byte[] data)
    {
        data = [];
        // Length gates: empty is malformed, oversized is poisoned (see above),
        // and no base64 string has length ≡ 1 (mod 4) — a cheap early out the
        // decoder would otherwise reject after the padding math.
        if (value.Length == 0 || value.Length > MaxBase64FieldChars || value.Length % 4 == 1)
        {
            return false;
        }

        // Re-pad to a multiple of 4 before standard Base64 decoding.
        int padding = value.Length % 4;
        string padded = padding == 0 ? value : value + new string('=', 4 - padding);
        Span<byte> buffer = new byte[((padded.Length) / 4) * 3];
        if (!Convert.TryFromBase64String(padded, buffer, out int written))
        {
            return false;
        }

        byte[] decoded = buffer[..written].ToArray();

        // Canonicality pin: exactly one accepted encoding per byte sequence.
        // Convert.TryFromBase64String silently skips whitespace and tolerates
        // non-zero trailing bits in the final character; both would let distinct
        // stored strings alias to the same bytes. Re-encoding and comparing
        // rejects every non-canonical form in one strict check.
        if (!EncodeNoPad(decoded).Equals(value, StringComparison.Ordinal))
        {
            return false;
        }

        data = decoded;
        return true;
    }
}
