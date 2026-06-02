# PostQuantum.Identity benchmarks

[BenchmarkDotNet](https://benchmarkdotnet.org/) measurements for the Argon2id
password hasher. The goal is to help you pick work factors that hit your latency
budget: **memory-hard hashing is meant to be slow** — the right setting is the
highest cost your sign-in SLO tolerates under peak concurrent load.

## Run

```bash
dotnet run -c Release -f net10.0 --project benchmarks/PostQuantum.Identity.Benchmarks

# Filter, e.g. only the hashing benchmark:
dotnet run -c Release -f net10.0 --project benchmarks/PostQuantum.Identity.Benchmarks -- --filter '*Hash*'

# Compare runtimes (the hasher works on all three TFMs):
dotnet run -c Release -f net8.0  --project benchmarks/PostQuantum.Identity.Benchmarks
dotnet run -c Release -f net9.0  --project benchmarks/PostQuantum.Identity.Benchmarks
```

## What it measures

Three operations across three work-factor profiles
(`owasp-min` 19 MiB/t=2, `balanced` 64 MiB/t=3, `hardened` 128 MiB/t=4):

- **HashPassword** — registration / password-change cost.
- **VerifyCorrect** — the hot sign-in path.
- **VerifyWrong** — must cost the same as a correct verification.

`[MemoryDiagnoser]` also reports allocations per call.

> Benchmark numbers are hardware-specific; run them on hardware representative of
> your production tier rather than trusting figures from another machine.

---

*To God be the glory — 1 Corinthians 10:31.*
