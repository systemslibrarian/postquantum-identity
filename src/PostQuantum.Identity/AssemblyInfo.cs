using System.Runtime.CompilerServices;

// The test project exercises the PHC parser/formatter and other internal seams
// directly. Production code never depends on this; it only widens visibility for
// the in-repo unit tests.
[assembly: InternalsVisibleTo("PostQuantum.Identity.Tests")]
