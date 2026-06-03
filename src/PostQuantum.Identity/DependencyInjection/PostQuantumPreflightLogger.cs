using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PostQuantum.Identity.DependencyInjection;

/// <summary>
/// Opt-in startup diagnostic that writes a single structured INFO log line
/// summarising the resolved PostQuantum.Identity configuration: Argon2id work
/// factors and approximate per-hash memory budget. Lets ops confirm at boot
/// what the running process actually picked up.
/// </summary>
/// <remarks>
/// <para>
/// Register with
/// <see cref="ServiceCollectionExtensions.AddPostQuantumPreflightLogging(IServiceCollection)"/>;
/// runs once when the host starts. Never logs key material, plaintext
/// passwords, or token contents.
/// </para>
/// </remarks>
internal sealed partial class PostQuantumPreflightLogger : IHostedService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<PostQuantumPreflightLogger> _logger;

    public PostQuantumPreflightLogger(
        IServiceProvider services,
        ILogger<PostQuantumPreflightLogger> logger)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(logger);
        _services = services;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        Argon2idOptions? argon2 = _services.GetService<IOptions<Argon2idOptions>>()?.Value;
        if (argon2 is null)
        {
            LogHasherNotRegistered(_logger);
            return Task.CompletedTask;
        }

        // Allocation is fine at startup; this fires once per process lifetime.
        string approx = string.Create(CultureInfo.InvariantCulture,
            $"~{argon2.MemorySizeKib / 1024} MiB allocated per hash invocation");
        LogPreflight(
            _logger,
            argon2.MemorySizeKib,
            argon2.Iterations,
            argon2.DegreeOfParallelism,
            argon2.SaltSizeBytes,
            argon2.HashSizeBytes,
            approx);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Information,
        Message = "PostQuantum.Identity preflight: Argon2id m={MemoryKib} KiB, t={Iterations}, p={Parallelism}, saltBytes={SaltSize}, tagBytes={TagSize} ({Approx}).")]
    private static partial void LogPreflight(
        ILogger logger,
        int memoryKib,
        int iterations,
        int parallelism,
        int saltSize,
        int tagSize,
        string approx);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Information,
        Message = "PostQuantum.Identity preflight: Argon2id hasher not registered.")]
    private static partial void LogHasherNotRegistered(ILogger logger);
}
