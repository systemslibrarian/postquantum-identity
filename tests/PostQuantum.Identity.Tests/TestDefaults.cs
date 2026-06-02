namespace PostQuantum.Identity.Tests;

/// <summary>
/// Fast, deliberately weak Argon2id parameters for the unit-test suite. These are
/// at the documented minimums so tests stay quick; production uses the
/// <see cref="Argon2idOptions.Recommended"/> defaults.
/// </summary>
internal static class TestDefaults
{
    public static Argon2idOptions FastOptions() => new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
        SaltSizeBytes = 16,
        HashSizeBytes = 32,
    };
}
