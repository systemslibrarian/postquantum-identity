using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using PostQuantum.Identity.DependencyInjection;
using Xunit;

namespace PostQuantum.Identity.Tests;

/// <summary>
/// Tests for the opt-in <c>AddPostQuantumPreflightLogging</c> hosted service.
/// Confirms it writes a single structured log line summarising the resolved
/// Argon2id configuration at startup, and that it never logs anything
/// sensitive (no key material, no passwords, no token contents).
/// </summary>
public class PreflightLoggerTests
{
    private sealed class TestUser
    {
        public string Id { get; init; } = Guid.NewGuid().ToString();
    }

    /// <summary>
    /// In-memory <see cref="ILoggerProvider"/> that captures every log record
    /// so the test can assert the preflight line landed with the expected
    /// parameters.
    /// </summary>
    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public List<(LogLevel Level, string Category, string Message)> Records { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this, categoryName);
        public void Dispose() { }

        private sealed class CapturingLogger(CapturingLoggerProvider parent, string category) : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? ex, Func<TState, Exception?, string> formatter)
            {
                parent.Records.Add((level, category, formatter(state, ex)));
            }

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new();
                public void Dispose() { }
            }
        }
    }

    [Fact]
    public async Task Preflight_logger_emits_argon2id_configuration_summary_on_startup()
    {
        CapturingLoggerProvider sink = new();
        ServiceCollection services = new();
        services.AddLogging(b => b.AddProvider(sink));
        services.AddArgon2idPasswordHasher<TestUser>(Argon2idOptions.OwaspMinimum());
        services.AddPostQuantumPreflightLogging();

        using ServiceProvider sp = services.BuildServiceProvider();
        IHostedService hosted = sp.GetRequiredService<IEnumerable<IHostedService>>().Single();
        await hosted.StartAsync(CancellationToken.None);

        // Exactly one preflight line landed, at INFO, with the right work factors.
        (LogLevel Level, string Category, string Message) record =
            Assert.Single(sink.Records, r => r.Message.Contains("PostQuantum.Identity preflight", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Contains("m=19456", record.Message, StringComparison.Ordinal);
        Assert.Contains("t=2", record.Message, StringComparison.Ordinal);
        Assert.Contains("p=1", record.Message, StringComparison.Ordinal);
        Assert.Contains("saltBytes=16", record.Message, StringComparison.Ordinal);
        Assert.Contains("tagBytes=32", record.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Preflight_logger_never_logs_anything_sensitive()
    {
        // A password / token / key the preflight could not possibly know — if any
        // of these ever appears in the log output, it would mean the logger has
        // started reaching into state it should never touch.
        const string PlaintextPasswordSentinel = "Lovelace#1843";
        const string TokenContentsSentinel = "eyJhbGciOi";   // JWT-shaped prefix
        const string PrivateKeyMaterialSentinel = "BEGIN PRIVATE KEY";

        CapturingLoggerProvider sink = new();
        ServiceCollection services = new();
        services.AddLogging(b => b.AddProvider(sink));
        services.AddArgon2idPasswordHasher<TestUser>(Argon2idOptions.HighSecurity());
        services.AddPostQuantumPreflightLogging();

        using ServiceProvider sp = services.BuildServiceProvider();
        IHostedService hosted = sp.GetRequiredService<IEnumerable<IHostedService>>().Single();
        await hosted.StartAsync(CancellationToken.None);

        string combined = string.Join("\n", sink.Records.Select(r => r.Message));
        Assert.DoesNotContain(PlaintextPasswordSentinel, combined, StringComparison.Ordinal);
        Assert.DoesNotContain(TokenContentsSentinel, combined, StringComparison.Ordinal);
        Assert.DoesNotContain(PrivateKeyMaterialSentinel, combined, StringComparison.Ordinal);
    }
}
