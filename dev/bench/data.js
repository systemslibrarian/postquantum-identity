window.BENCHMARK_DATA = {
  "lastUpdate": 1783026575024,
  "repoUrl": "https://github.com/systemslibrarian/postquantum-identity",
  "entries": {
    "Argon2id benchmarks": [
      {
        "commit": {
          "author": {
            "email": "paul@systemslibrarian.dev",
            "name": "Paul Clark",
            "username": "systemslibrarian"
          },
          "committer": {
            "email": "paul@systemslibrarian.dev",
            "name": "Paul Clark",
            "username": "systemslibrarian"
          },
          "distinct": true,
          "id": "ab70f2549bc9273f8c63518ae76559190f492100",
          "message": "fix(ci): pin conda OpenSSL to the 3.x series for the Linux PQ-required lane\n\nconda-forge now resolves an unbounded openssl>=3.5 to OpenSSL 4.0.1, and the\n.NET 10 BCL PQC path binds libcrypto.so.3 - MLDsa.IsSupported came back\nfalse and all 21 PQ tests skipped, which the zero-skip gate correctly turned\ninto a lane failure. Pin to >=3.5,<4 and document the 3.x requirement in\nTROUBLESHOOTING (an OpenSSL 4.x install does not satisfy the BCL).\n\nCo-Authored-By: Claude Fable 5 <noreply@anthropic.com>",
          "timestamp": "2026-07-02T17:07:10-04:00",
          "tree_id": "d6da72894bb7744b065b51aa0aa54d1bb0f29000",
          "url": "https://github.com/systemslibrarian/postquantum-identity/commit/ab70f2549bc9273f8c63518ae76559190f492100"
        },
        "date": 1783026574591,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"balanced:65536:3\")",
            "value": 512228270,
            "unit": "ns",
            "range": "± 1761489.5683889247"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"balanced:65536:3\")",
            "value": 512748194.6666667,
            "unit": "ns",
            "range": "± 1055938.2045983246"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"balanced:65536:3\")",
            "value": 515289541.6666667,
            "unit": "ns",
            "range": "± 1245457.5648155713"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"hardened:131072:4\")",
            "value": 1385662288.3333333,
            "unit": "ns",
            "range": "± 1026972.8815184621"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"hardened:131072:4\")",
            "value": 1385155973,
            "unit": "ns",
            "range": "± 3971519.0768461633"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"hardened:131072:4\")",
            "value": 1385090439,
            "unit": "ns",
            "range": "± 3268883.107593173"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"owasp-min:19456:2\")",
            "value": 100390463.86666667,
            "unit": "ns",
            "range": "± 612506.5545017244"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"owasp-min:19456:2\")",
            "value": 101312056.86666667,
            "unit": "ns",
            "range": "± 110434.39408451384"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"owasp-min:19456:2\")",
            "value": 101452344.86666667,
            "unit": "ns",
            "range": "± 333737.985821356"
          }
        ]
      }
    ]
  }
}