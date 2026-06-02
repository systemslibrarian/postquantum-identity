using BenchmarkDotNet.Running;
using PostQuantum.Identity.Benchmarks;

// Run all benchmarks (or filter with --filter '*Hash*'):
//   dotnet run -c Release -f net10.0 --project benchmarks/PostQuantum.Identity.Benchmarks
BenchmarkSwitcher.FromAssembly(typeof(Argon2idBenchmarks).Assembly).Run(args);
