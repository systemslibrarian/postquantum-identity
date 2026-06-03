using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PostQuantum.Identity.DependencyInjection;
using Xunit;

namespace PostQuantum.Identity.Tests;

/// <summary>
/// Tests proving that a misconfigured <see cref="Argon2idOptions"/> surfaces at
/// host-startup time (via <see cref="IValidateOptions{TOptions}"/>) rather than
/// silently waiting until the first hash attempt and then blowing up in
/// production. Enterprise deployments want fail-fast at boot.
/// </summary>
public class Argon2idStartupValidationTests
{
    private sealed class TestUser
    {
        public string Id { get; init; } = Guid.NewGuid().ToString();
    }

    /// <summary>
    /// A configuration below the 8 MiB memory floor must fail
    /// <see cref="OptionsFactory{TOptions}"/> validation when
    /// <c>IOptions&lt;Argon2idOptions&gt;.Value</c> is resolved at startup, with a
    /// message that names the offending property and the bad value.
    /// </summary>
    [Fact]
    public void Insecure_memory_setting_fails_at_options_resolution()
    {
        ServiceCollection services = new();
        services.AddArgon2idPasswordHasher<TestUser>(o => o.MemorySizeKib = 1024);
        using ServiceProvider sp = services.BuildServiceProvider();

        OptionsValidationException ex = Assert.Throws<OptionsValidationException>(
            () => sp.GetRequiredService<IOptions<Argon2idOptions>>().Value);
        Assert.Contains("MemorySizeKib", ex.Message, StringComparison.Ordinal);
        Assert.Contains("1024", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Iterations = 0 (below the minimum of 1) must fail with a message that
    /// pinpoints the offending property.
    /// </summary>
    [Fact]
    public void Zero_iterations_fails_at_options_resolution()
    {
        ServiceCollection services = new();
        services.AddArgon2idPasswordHasher<TestUser>(o => o.Iterations = 0);
        using ServiceProvider sp = services.BuildServiceProvider();

        OptionsValidationException ex = Assert.Throws<OptionsValidationException>(
            () => sp.GetRequiredService<IOptions<Argon2idOptions>>().Value);
        Assert.Contains("Iterations", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>A valid configuration resolves without throwing.</summary>
    [Fact]
    public void Valid_configuration_resolves_cleanly()
    {
        ServiceCollection services = new();
        services.AddArgon2idPasswordHasher<TestUser>(Argon2idOptions.OwaspMinimum());
        using ServiceProvider sp = services.BuildServiceProvider();

        Argon2idOptions resolved = sp.GetRequiredService<IOptions<Argon2idOptions>>().Value;
        Assert.Equal(19456, resolved.MemorySizeKib);
    }
}
