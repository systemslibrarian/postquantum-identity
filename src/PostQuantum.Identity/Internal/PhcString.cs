using System.Globalization;

namespace PostQuantum.Identity.Internal;

/// <summary>
/// Parses and formats Argon2id hashes in the PHC string format
/// (<c>$argon2id$v=19$m=&lt;mem&gt;,t=&lt;iter&gt;,p=&lt;par&gt;$&lt;salt&gt;$&lt;hash&gt;</c>),
/// the de-facto interop format produced by the reference Argon2 CLI, libsodium,
/// and most modern hashing libraries.
/// </summary>
/// <remarks>
/// Salt and hash are Base64 encoded <b>without</b> padding, per the PHC spec.
/// Parsing is strict and fail-closed: any malformed field yields
/// <see langword="false"/> from <see cref="TryParse"/> rather than a partial
/// result, so a corrupt stored value can never be coaxed into a "match".
/// </remarks>
internal sealed record PhcString
{
    /// <summary>The Argon2 variant identifier. This library only emits/accepts <c>argon2id</c>.</summary>
    public const string Argon2idId = "argon2id";

    /// <summary>The Argon2 version number this library emits (0x13 == 19).</summary>
    public const int Argon2Version13 = 19;

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

        if (!TryDecodeNoPad(parts[4], out byte[]? salt)
            || !TryDecodeNoPad(parts[5], out byte[]? hash)
            || salt.Length == 0
            || hash.Length == 0)
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

        return int.TryParse(
            segment.AsSpan(tag.Length + 1),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out value);
    }

    private static string EncodeNoPad(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=');

    private static bool TryDecodeNoPad(string value, out byte[] data)
    {
        // Re-pad to a multiple of 4 before standard Base64 decoding.
        int padding = value.Length % 4;
        string padded = padding == 0 ? value : value + new string('=', 4 - padding);
        Span<byte> buffer = new byte[((padded.Length) / 4) * 3];
        if (Convert.TryFromBase64String(padded, buffer, out int written))
        {
            data = buffer[..written].ToArray();
            return true;
        }

        data = [];
        return false;
    }
}
