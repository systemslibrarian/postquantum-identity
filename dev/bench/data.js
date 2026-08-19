window.BENCHMARK_DATA = {
  "lastUpdate": 1787118295044,
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
      },
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
          "id": "0702bb53376afcfb401c7dd0def68c58fbeb6a03",
          "message": "release: 1.0.0 - stable API on stable upstream, scoped honestly\n\nThe 1.0 version is a semver commitment (public API breaks only with a major\nversion) built on PostQuantum.Jwt 1.0.0 stable - explicitly NOT an audit\nclaim. The README Roadmap-to-1.0 gate table becomes What 1.0 means - and\nwhat it does not (semver + stable upstream + closed engineering gates on\none side; no audit, no generic-JWT interop on the other) with a post-1.0\nroadmap. SECURITY.md, KNOWN-GAPS.md, threat model, production checklist,\nand security-review checklist re-aligned in lockstep; the unaudited and\nnon-interoperable statements are unchanged in substance everywhere.\n\nCo-Authored-By: Claude Fable 5 <noreply@anthropic.com>",
          "timestamp": "2026-07-02T17:41:49-04:00",
          "tree_id": "5a1a3ce3cac58dd83e07d47a73ccfb9d6171a9e4",
          "url": "https://github.com/systemslibrarian/postquantum-identity/commit/0702bb53376afcfb401c7dd0def68c58fbeb6a03"
        },
        "date": 1783028633801,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"balanced:65536:3\")",
            "value": 518939787.6666667,
            "unit": "ns",
            "range": "± 1160804.401965436"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"balanced:65536:3\")",
            "value": 518017958.3333333,
            "unit": "ns",
            "range": "± 684946.6797396227"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"balanced:65536:3\")",
            "value": 513265188,
            "unit": "ns",
            "range": "± 704083.5262687233"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"hardened:131072:4\")",
            "value": 1389468279.3333333,
            "unit": "ns",
            "range": "± 1203630.5728380005"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"hardened:131072:4\")",
            "value": 1384874648.3333333,
            "unit": "ns",
            "range": "± 1141593.8214922738"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"hardened:131072:4\")",
            "value": 1381659371,
            "unit": "ns",
            "range": "± 2163565.03547201"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"owasp-min:19456:2\")",
            "value": 100595756.26666665,
            "unit": "ns",
            "range": "± 348255.84399831103"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"owasp-min:19456:2\")",
            "value": 101857202.93333334,
            "unit": "ns",
            "range": "± 684445.2947566011"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"owasp-min:19456:2\")",
            "value": 102208074.2,
            "unit": "ns",
            "range": "± 119895.31394795729"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "692e9af5984a2d1ab0d902e517a30fc76543344b",
          "message": "Build(deps): Bump conda-incubator/setup-miniconda from 3 to 4 (#1)\n\nBumps [conda-incubator/setup-miniconda](https://github.com/conda-incubator/setup-miniconda) from 3 to 4.\n- [Release notes](https://github.com/conda-incubator/setup-miniconda/releases)\n- [Changelog](https://github.com/conda-incubator/setup-miniconda/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/conda-incubator/setup-miniconda/compare/v3...v4)\n\n---\nupdated-dependencies:\n- dependency-name: conda-incubator/setup-miniconda\n  dependency-version: '4'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-19T01:37:55-04:00",
          "tree_id": "5e5fc428d1b46f2d87a5a3da5fb6e74cf887fee8",
          "url": "https://github.com/systemslibrarian/postquantum-identity/commit/692e9af5984a2d1ab0d902e517a30fc76543344b"
        },
        "date": 1787118294597,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"balanced:65536:3\")",
            "value": 511088251.6666667,
            "unit": "ns",
            "range": "± 2090023.896717292"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"balanced:65536:3\")",
            "value": 514573456.3333333,
            "unit": "ns",
            "range": "± 4684223.856733614"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"balanced:65536:3\")",
            "value": 506327564,
            "unit": "ns",
            "range": "± 1588143.1676734942"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"hardened:131072:4\")",
            "value": 1384877577.3333333,
            "unit": "ns",
            "range": "± 2299538.657400726"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"hardened:131072:4\")",
            "value": 1371754084,
            "unit": "ns",
            "range": "± 253200.11330763658"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"hardened:131072:4\")",
            "value": 1380117286,
            "unit": "ns",
            "range": "± 667163.4980692514"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"owasp-min:19456:2\")",
            "value": 99439071.55555554,
            "unit": "ns",
            "range": "± 58005.14515740125"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"owasp-min:19456:2\")",
            "value": 100942784.93333332,
            "unit": "ns",
            "range": "± 154980.92319538514"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"owasp-min:19456:2\")",
            "value": 99450666.73333333,
            "unit": "ns",
            "range": "± 405626.961149153"
          }
        ]
      }
    ]
  }
}