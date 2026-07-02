using System.Security.Cryptography;

// ---------------------------------------------------------------------------
// PostQuantum.Identity key tool — the missing "provision an ML-DSA-65 key out
// of band" step, made concrete. Generates and inspects ML-DSA-65 signing keys
// in standard container formats:
//
//   generate --kid <id> [--out <dir>] [--password <pw>]
//       -> <kid>.private.pem   PKCS#8 (AES-256-CBC + PBKDF2-SHA256 when a
//                              password is given; plaintext PKCS#8 otherwise)
//       -> <kid>.public.pem    SubjectPublicKeyInfo — this is the half your
//                              verifiers hold
//
//   inspect <path> [--password <pw>]
//       -> algorithm + SPKI SHA-256 fingerprint, for either half
//
// Honesty notes, so nobody mistakes this for more than it is:
//   * A PEM file on disk is the *floor* for key custody, not the goal. Prefer
//     a KMS / HSM / secret store in production; this tool exists because every
//     deployment needs a provisioning step and "out of band" is not a recipe.
//   * The tool never prints private-key material and zeroes the PKCS#8 bytes
//     after writing, but the OS file itself is only as safe as its ACLs —
//     restrict them (chmod 600 / icacls) and treat the file like a credential.
//   * Everything here is the .NET 10 BCL. No third-party crypto.
// ---------------------------------------------------------------------------

// OWASP-recommended PBKDF2-SHA256 work factor (2023 guidance) for the PKCS#8
// password-based encryption. Slow on purpose — this runs once per key.
const int Pbkdf2Iterations = 600_000;

if (!MLDsa.IsSupported)
{
    Console.Error.WriteLine(
        "ML-DSA is not available on this host. It needs the .NET 10 BCL post-quantum "
        + "primitives (Windows CNG on Windows 11 / Server 2022+, OpenSSL 3.5+ on Linux).");
    return 2;
}

try
{
    return args switch
    {
        ["generate", .. string[] rest] => Generate(ParseOptions(rest)),
        ["inspect", string path, .. string[] rest] => Inspect(path, ParseOptions(rest)),
        _ => Usage(),
    };
}
catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException or FormatException)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 1;
}

static int Generate(Dictionary<string, string> options)
{
    if (!options.TryGetValue("kid", out string? kid) || string.IsNullOrWhiteSpace(kid))
    {
        Console.Error.WriteLine("generate requires --kid <id>. Date-based names (e.g. k-2026-07) make rotation windows self-documenting.");
        return 1;
    }

    if (kid.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
    {
        Console.Error.WriteLine("error: --kid must be usable as a file name.");
        return 1;
    }

    string outDir = options.GetValueOrDefault("out", ".");
    Directory.CreateDirectory(outDir);
    string privatePath = Path.Combine(outDir, kid + ".private.pem");
    string publicPath = Path.Combine(outDir, kid + ".public.pem");

    // Refuse to overwrite: silently replacing a signing key would strand every
    // token already issued under this kid.
    if (File.Exists(privatePath) || File.Exists(publicPath))
    {
        Console.Error.WriteLine($"error: {kid}.private.pem / {kid}.public.pem already exist in {outDir}. Pick a new kid — rotation means adding a key, not replacing one in place.");
        return 1;
    }

    string? password = options.GetValueOrDefault("password");

    using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    byte[] spki = key.ExportSubjectPublicKeyInfo();
    byte[] pkcs8 = password is null
        ? key.ExportPkcs8PrivateKey()
        : key.ExportEncryptedPkcs8PrivateKey(
            password,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, Pbkdf2Iterations));

    try
    {
        File.WriteAllText(privatePath, PemEncoding.WriteString(
            password is null ? "PRIVATE KEY" : "ENCRYPTED PRIVATE KEY", pkcs8));
    }
    finally
    {
        // The PEM file is the sanctioned copy; don't leave a second one on the heap.
        CryptographicOperations.ZeroMemory(pkcs8);
    }

    File.WriteAllText(publicPath, PemEncoding.WriteString("PUBLIC KEY", spki));

    Console.WriteLine($"kid:          {kid}");
    Console.WriteLine("algorithm:    ML-DSA-65 (FIPS 204)");
    Console.WriteLine($"fingerprint:  {Fingerprint(spki)}");
    Console.WriteLine($"private key:  {privatePath}");
    Console.WriteLine($"public key:   {publicPath}   <- distribute this half to verifiers");

    if (password is null)
    {
        Console.WriteLine();
        Console.WriteLine("WARNING: the private key was written UNENCRYPTED (no --password).");
        Console.WriteLine("Restrict the file's ACLs now (chmod 600 / icacls) and treat it as a credential.");
    }

    Console.WriteLine();
    Console.WriteLine("Next steps: load the private half in your issuer's AddPostQuantumTokens options");
    Console.WriteLine("(SigningKey + KeyId), and hand only the .public.pem to verifiers. Prefer a");
    Console.WriteLine("KMS/HSM/secret store where you have one — PEM-on-disk is the portable floor.");
    return 0;
}

static int Inspect(string path, Dictionary<string, string> options)
{
    string pem = File.ReadAllText(path);
    if (!PemEncoding.TryFind(pem, out PemFields fields))
    {
        Console.Error.WriteLine($"error: no PEM block found in {path}.");
        return 1;
    }

    // The label sniff is only for friendly errors; the import itself uses the
    // BCL PEM readers (native BCL first — no hand-rolled base64/DER handling,
    // and no intermediate private-key buffer for us to zero).
    string label = pem[fields.Label];
    using MLDsa key = label switch
    {
        "PUBLIC KEY" or "PRIVATE KEY" => MLDsa.ImportFromPem(pem),
        "ENCRYPTED PRIVATE KEY" when options.TryGetValue("password", out string? pw)
            => MLDsa.ImportFromEncryptedPem(pem, pw),
        "ENCRYPTED PRIVATE KEY"
            => throw new CryptographicException("this private key is encrypted — pass --password <pw> to inspect it."),
        _ => throw new CryptographicException($"unsupported PEM label \"{label}\" (expected PUBLIC KEY / PRIVATE KEY / ENCRYPTED PRIVATE KEY)."),
    };

    string fingerprint = Fingerprint(key.ExportSubjectPublicKeyInfo());
    Console.WriteLine($"file:         {path}");
    Console.WriteLine($"contains:     {label}");
    Console.WriteLine($"algorithm:    {key.Algorithm.Name}");
    Console.WriteLine($"fingerprint:  {fingerprint}");
    Console.WriteLine($"suggested kid: {fingerprint[..16]}   (or keep your date-based naming)");
    return 0;
}

// SHA-256 over the SubjectPublicKeyInfo DER — a stable identifier for "is this
// the same key?" across machines, formats, and JWKS documents.
static string Fingerprint(byte[] spki) =>
    Convert.ToHexStringLower(SHA256.HashData(spki));

static Dictionary<string, string> ParseOptions(string[] rest)
{
    var options = new Dictionary<string, string>(StringComparer.Ordinal);
    for (int i = 0; i < rest.Length; i += 2)
    {
        if (!rest[i].StartsWith("--", StringComparison.Ordinal))
        {
            throw new FormatException($"expected an --option, got \"{rest[i]}\".");
        }

        // Fail closed on a dangling or value-less flag. Silently dropping a
        // trailing "--password" would write an UNENCRYPTED private key the
        // operator believed was protected — the worst possible parse "recovery"
        // for a key-provisioning tool.
        if (i + 1 >= rest.Length || rest[i + 1].StartsWith("--", StringComparison.Ordinal))
        {
            throw new FormatException($"option \"{rest[i]}\" is missing a value.");
        }

        options[rest[i][2..]] = rest[i + 1];
    }

    return options;
}

static int Usage()
{
    Console.WriteLine("PostQuantum.Identity key tool — provision ML-DSA-65 signing keys out of band.");
    Console.WriteLine();
    Console.WriteLine("usage:");
    Console.WriteLine("  generate --kid <id> [--out <dir>] [--password <pw>]");
    Console.WriteLine("  inspect <path> [--password <pw>]");
    Console.WriteLine();
    Console.WriteLine("examples:");
    Console.WriteLine("  dotnet run -- generate --kid k-2026-07 --out ./keys --password s3cret");
    Console.WriteLine("  dotnet run -- inspect ./keys/k-2026-07.public.pem");
    return 1;
}
