window.BENCHMARK_DATA = {
  "lastUpdate": 1787121481405,
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
          "id": "f73e14d8c3d70ddac577cad06a0e598e0deb349e",
          "message": "Build(deps): Bump actions/attest-build-provenance from 3 to 4 (#2)\n\nBumps [actions/attest-build-provenance](https://github.com/actions/attest-build-provenance) from 3 to 4.\n- [Release notes](https://github.com/actions/attest-build-provenance/releases)\n- [Changelog](https://github.com/actions/attest-build-provenance/blob/main/RELEASE.md)\n- [Commits](https://github.com/actions/attest-build-provenance/compare/v3...v4)\n\n---\nupdated-dependencies:\n- dependency-name: actions/attest-build-provenance\n  dependency-version: '4'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-19T01:37:58-04:00",
          "tree_id": "6bdd44c064018003f8bb7b6200077525c81bd6fc",
          "url": "https://github.com/systemslibrarian/postquantum-identity/commit/f73e14d8c3d70ddac577cad06a0e598e0deb349e"
        },
        "date": 1787118982176,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"balanced:65536:3\")",
            "value": 519142045.3333333,
            "unit": "ns",
            "range": "± 1670480.5596391517"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"balanced:65536:3\")",
            "value": 515035862,
            "unit": "ns",
            "range": "± 1695563.34585323"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"balanced:65536:3\")",
            "value": 513581727,
            "unit": "ns",
            "range": "± 2261048.233639433"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"hardened:131072:4\")",
            "value": 1384592637.3333333,
            "unit": "ns",
            "range": "± 4056161.996120758"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"hardened:131072:4\")",
            "value": 1391276956,
            "unit": "ns",
            "range": "± 5608724.4838685915"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"hardened:131072:4\")",
            "value": 1395885910.6666667,
            "unit": "ns",
            "range": "± 2265317.897760562"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"owasp-min:19456:2\")",
            "value": 105276470.86666667,
            "unit": "ns",
            "range": "± 510082.7487938174"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"owasp-min:19456:2\")",
            "value": 104168213.13333333,
            "unit": "ns",
            "range": "± 260696.77984250782"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"owasp-min:19456:2\")",
            "value": 104716152.26666667,
            "unit": "ns",
            "range": "± 436302.59986744943"
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
          "id": "7dfc89f42f92690d7e36f483eb9a9cb81aba7b13",
          "message": "Build(deps): Bump actions/upload-artifact from 5 to 7 (#3)\n\nBumps [actions/upload-artifact](https://github.com/actions/upload-artifact) from 5 to 7.\n- [Release notes](https://github.com/actions/upload-artifact/releases)\n- [Commits](https://github.com/actions/upload-artifact/compare/v5...v7)\n\n---\nupdated-dependencies:\n- dependency-name: actions/upload-artifact\n  dependency-version: '7'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-19T01:38:02-04:00",
          "tree_id": "c4f60c9745c770f8a266793b8be75c842ce3a45e",
          "url": "https://github.com/systemslibrarian/postquantum-identity/commit/7dfc89f42f92690d7e36f483eb9a9cb81aba7b13"
        },
        "date": 1787119102944,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"balanced:65536:3\")",
            "value": 268095151.66666666,
            "unit": "ns",
            "range": "± 1159135.2937970974"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"balanced:65536:3\")",
            "value": 267237555.5,
            "unit": "ns",
            "range": "± 413209.02819063625"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"balanced:65536:3\")",
            "value": 268154642,
            "unit": "ns",
            "range": "± 700854.86082373"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"hardened:131072:4\")",
            "value": 730505278.3333334,
            "unit": "ns",
            "range": "± 1707137.2668664735"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"hardened:131072:4\")",
            "value": 730729597.3333334,
            "unit": "ns",
            "range": "± 1177413.586928711"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"hardened:131072:4\")",
            "value": 732400412.3333334,
            "unit": "ns",
            "range": "± 1683610.9328610732"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"owasp-min:19456:2\")",
            "value": 52295288.800000004,
            "unit": "ns",
            "range": "± 41676.906273379616"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"owasp-min:19456:2\")",
            "value": 52315094.36666667,
            "unit": "ns",
            "range": "± 80983.60952540711"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"owasp-min:19456:2\")",
            "value": 52319272.43333334,
            "unit": "ns",
            "range": "± 145387.44820101754"
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
          "id": "435c536576a4c06451bc8b9b13a64c45c503c66d",
          "message": "Build(deps): Bump actions/download-artifact from 5 to 8 (#5)\n\nBumps [actions/download-artifact](https://github.com/actions/download-artifact) from 5 to 8.\n- [Release notes](https://github.com/actions/download-artifact/releases)\n- [Commits](https://github.com/actions/download-artifact/compare/v5...v8)\n\n---\nupdated-dependencies:\n- dependency-name: actions/download-artifact\n  dependency-version: '8'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-19T01:38:10-04:00",
          "tree_id": "6f8174db35e51d63b7e58f70fff801426ff418e0",
          "url": "https://github.com/systemslibrarian/postquantum-identity/commit/435c536576a4c06451bc8b9b13a64c45c503c66d"
        },
        "date": 1787119386495,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"balanced:65536:3\")",
            "value": 518728468.3333333,
            "unit": "ns",
            "range": "± 322083.50272923533"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"balanced:65536:3\")",
            "value": 522097863,
            "unit": "ns",
            "range": "± 2435007.536802094"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"balanced:65536:3\")",
            "value": 520895087,
            "unit": "ns",
            "range": "± 3042091.052912618"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"hardened:131072:4\")",
            "value": 1393734516,
            "unit": "ns",
            "range": "± 1250460.3937250471"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"hardened:131072:4\")",
            "value": 1392102475.3333333,
            "unit": "ns",
            "range": "± 3169054.2769263727"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"hardened:131072:4\")",
            "value": 1388726304,
            "unit": "ns",
            "range": "± 991781.4834952304"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"owasp-min:19456:2\")",
            "value": 101974196,
            "unit": "ns",
            "range": "± 105843.22786990716"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"owasp-min:19456:2\")",
            "value": 103799746.13333333,
            "unit": "ns",
            "range": "± 740951.2169995926"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"owasp-min:19456:2\")",
            "value": 102998051.73333333,
            "unit": "ns",
            "range": "± 71260.79497320774"
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
          "id": "c9adae55925cd43e7e9d14227de0d19229678f00",
          "message": "Bump coverlet.collector from 6.0.2 to 10.0.1 (#7)\n\n---\nupdated-dependencies:\n- dependency-name: coverlet.collector\n  dependency-version: 10.0.1\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-19T01:38:13-04:00",
          "tree_id": "82219cf707f5331ab82ac9a5bb727c09375ff067",
          "url": "https://github.com/systemslibrarian/postquantum-identity/commit/c9adae55925cd43e7e9d14227de0d19229678f00"
        },
        "date": 1787119575218,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"balanced:65536:3\")",
            "value": 295972381.5,
            "unit": "ns",
            "range": "± 2359292.635574697"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"balanced:65536:3\")",
            "value": 295284305.1666667,
            "unit": "ns",
            "range": "± 2351117.024500766"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"balanced:65536:3\")",
            "value": 305135146.3333333,
            "unit": "ns",
            "range": "± 1019496.6623047785"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"hardened:131072:4\")",
            "value": 802201470.6666666,
            "unit": "ns",
            "range": "± 9472373.520139836"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"hardened:131072:4\")",
            "value": 798854843,
            "unit": "ns",
            "range": "± 4289862.588048363"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"hardened:131072:4\")",
            "value": 792616639.3333334,
            "unit": "ns",
            "range": "± 942129.1508754696"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"owasp-min:19456:2\")",
            "value": 59374576.629629634,
            "unit": "ns",
            "range": "± 337921.244160134"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"owasp-min:19456:2\")",
            "value": 58268309.96296296,
            "unit": "ns",
            "range": "± 94109.34247743075"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"owasp-min:19456:2\")",
            "value": 58685896.55555556,
            "unit": "ns",
            "range": "± 91107.73495784136"
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
          "id": "aeda3bb309bffd2b451e40bff84afa63ec917bf9",
          "message": "Bump Microsoft.AspNetCore.Identity.EntityFrameworkCore from 10.0.0 to 10.0.11 (#26)\n\n---\nupdated-dependencies:\n- dependency-name: Microsoft.AspNetCore.Identity.EntityFrameworkCore\n  dependency-version: 10.0.11\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n- dependency-name: Microsoft.AspNetCore.Identity.EntityFrameworkCore\n  dependency-version: 10.0.11\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-19T01:38:16-04:00",
          "tree_id": "1aae4f675d729a299fc9ce6830f595f6e3aa6970",
          "url": "https://github.com/systemslibrarian/postquantum-identity/commit/aeda3bb309bffd2b451e40bff84afa63ec917bf9"
        },
        "date": 1787119890719,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"balanced:65536:3\")",
            "value": 514962376.3333333,
            "unit": "ns",
            "range": "± 2736640.4192303624"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"balanced:65536:3\")",
            "value": 513809233.3333333,
            "unit": "ns",
            "range": "± 830297.9526208247"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"balanced:65536:3\")",
            "value": 520138284,
            "unit": "ns",
            "range": "± 1667047.5257616383"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"hardened:131072:4\")",
            "value": 1393797398.6666667,
            "unit": "ns",
            "range": "± 974254.9605787663"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"hardened:131072:4\")",
            "value": 1394568228,
            "unit": "ns",
            "range": "± 3340416.8232591874"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"hardened:131072:4\")",
            "value": 1395354264.3333333,
            "unit": "ns",
            "range": "± 2796810.5062642936"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"owasp-min:19456:2\")",
            "value": 103572613.53333335,
            "unit": "ns",
            "range": "± 383158.1194369953"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"owasp-min:19456:2\")",
            "value": 104401448.66666667,
            "unit": "ns",
            "range": "± 463252.536098159"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"owasp-min:19456:2\")",
            "value": 103195700.2,
            "unit": "ns",
            "range": "± 180842.9906628386"
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
          "id": "eada416121a17d29cc80a6589713c7bb303c283c",
          "message": "Bump Microsoft.Extensions.Hosting.Abstractions from 8.0.0 to 10.0.11 (#28)\n\n---\nupdated-dependencies:\n- dependency-name: Microsoft.Extensions.Hosting.Abstractions\n  dependency-version: 10.0.11\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-19T01:38:20-04:00",
          "tree_id": "ddd474825a13ebc98b862c46144deef5c8b08a50",
          "url": "https://github.com/systemslibrarian/postquantum-identity/commit/eada416121a17d29cc80a6589713c7bb303c283c"
        },
        "date": 1787120544391,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"balanced:65536:3\")",
            "value": 513254034,
            "unit": "ns",
            "range": "± 1463336.2980080827"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"balanced:65536:3\")",
            "value": 511001558.3333333,
            "unit": "ns",
            "range": "± 1109705.4751195624"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"balanced:65536:3\")",
            "value": 515205104.6666667,
            "unit": "ns",
            "range": "± 1118407.7688143682"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"hardened:131072:4\")",
            "value": 1383840027.3333333,
            "unit": "ns",
            "range": "± 1537579.779892521"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"hardened:131072:4\")",
            "value": 1380966553.3333333,
            "unit": "ns",
            "range": "± 699886.5853281753"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"hardened:131072:4\")",
            "value": 1382111520.6666667,
            "unit": "ns",
            "range": "± 1416569.0638356935"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"owasp-min:19456:2\")",
            "value": 101035984.13333333,
            "unit": "ns",
            "range": "± 342369.550129468"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"owasp-min:19456:2\")",
            "value": 101396082.40000002,
            "unit": "ns",
            "range": "± 206268.7143877165"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"owasp-min:19456:2\")",
            "value": 100524432.86666667,
            "unit": "ns",
            "range": "± 436788.832314758"
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
          "id": "c21bdde1621d498aa678396775cd66f0929c75c6",
          "message": "Bump Microsoft.EntityFrameworkCore.InMemory from 10.0.0 to 10.0.11 (#27)\n\n---\nupdated-dependencies:\n- dependency-name: Microsoft.EntityFrameworkCore.InMemory\n  dependency-version: 10.0.11\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n- dependency-name: Microsoft.EntityFrameworkCore.InMemory\n  dependency-version: 10.0.11\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-19T01:43:22-04:00",
          "tree_id": "17c1b8325fb38fa5b3d8278524d659a37e13fd49",
          "url": "https://github.com/systemslibrarian/postquantum-identity/commit/c21bdde1621d498aa678396775cd66f0929c75c6"
        },
        "date": 1787121480477,
        "tool": "benchmarkdotnet",
        "benches": [
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"balanced:65536:3\")",
            "value": 516872906,
            "unit": "ns",
            "range": "± 1086232.819743079"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"balanced:65536:3\")",
            "value": 525975748,
            "unit": "ns",
            "range": "± 2665219.3999976814"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"balanced:65536:3\")",
            "value": 521018897.3333333,
            "unit": "ns",
            "range": "± 2385296.416071247"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"hardened:131072:4\")",
            "value": 1388135738.6666667,
            "unit": "ns",
            "range": "± 4765111.927360608"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"hardened:131072:4\")",
            "value": 1386199830.3333333,
            "unit": "ns",
            "range": "± 2285217.4287822885"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"hardened:131072:4\")",
            "value": 1395912959.6666667,
            "unit": "ns",
            "range": "± 2784915.295883222"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.HashPassword(Profile: \"owasp-min:19456:2\")",
            "value": 101719864,
            "unit": "ns",
            "range": "± 617486.4511626445"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyCorrect(Profile: \"owasp-min:19456:2\")",
            "value": 101356637.46666665,
            "unit": "ns",
            "range": "± 363011.38667376316"
          },
          {
            "name": "PostQuantum.Identity.Benchmarks.Argon2idBenchmarks.VerifyWrong(Profile: \"owasp-min:19456:2\")",
            "value": 100791770.13333333,
            "unit": "ns",
            "range": "± 75663.24093516963"
          }
        ]
      }
    ]
  }
}