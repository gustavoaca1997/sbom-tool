using System.Collections.Generic;
using System.IO;
using Microsoft.Build.Framework;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Targets.Tests.Utility;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Targets.Tests;

/// <summary>
/// Base class for testing SBOM generation through the GenerateSbomTask.
/// </summary>
[TestClass]
public abstract class AbstractGenerateSbomTaskTests
{
    internal abstract SbomSpecification SbomSpecification { get; }

    internal static readonly string CurrentDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    internal static readonly string DefaultManifestDirectory = Path.Combine(CurrentDirectory, "_manifest");
    internal static readonly string TemporaryDirectory = Path.Combine(CurrentDirectory, "_temp");
    internal const string PackageSupplier = "Test-Microsoft";
    internal const string PackageName = "CoseSignTool";
    internal const string PackageVersion = "0.0.1";
    internal const string NamespaceBaseUri = "https://base0.uri";

    internal Mock<IBuildEngine> BuildEngine;
    internal List<BuildErrorEventArgs> Errors;
    internal string ManifestPath;
    internal GeneratedSbomValidator GeneratedSbomValidator;

    internal string SbomSpecificationDirectoryName => $"{this.SbomSpecification.Name}_{this.SbomSpecification.Version}".ToLowerInvariant();

    [TestInitialize]
    public void Startup()
    {
        // Setup the build engine
        this.BuildEngine = new Mock<IBuildEngine>();
        this.Errors = new List<BuildErrorEventArgs>();
        this.BuildEngine.Setup(x => x.LogErrorEvent(It.IsAny<BuildErrorEventArgs>())).Callback<BuildErrorEventArgs>(e => Errors.Add(e));

        // Clean up the manifest directory
        if (Directory.Exists(DefaultManifestDirectory))
        {
            Directory.Delete(DefaultManifestDirectory, true);
        }

        // Clean up the manifest directory
        if (Directory.Exists(TemporaryDirectory))
        {
            Directory.Delete(TemporaryDirectory, true);
        }

        this.ManifestPath = Path.Combine(DefaultManifestDirectory, this.SbomSpecificationDirectoryName, "manifest.spdx.json");
        this.GeneratedSbomValidator = new(this.SbomSpecification);
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.GeneratedSbomValidator.AssertSbomIsValid(this.ManifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSupplier, NamespaceBaseUri);
    }

    [TestMethod]
    [DataRow("http://example.com/hello/world")] // Regular valid URI
    [DataRow("http://example.com/hello%20world")] // Valid URI with space encoded
    [DataRow("http://ExAmplE.com")] // Mix of cases
    [DataRow("  http://example.com  ")] // Trailing spaces
    [DataRow("http://www.example.com/path/to/resource?param1=value1&param2=value2&param3=value3&param4=value4&param5=" +
        "value5&param6=value6&param7=value7&param8=value8&param9=value9&param10=value10&param11=value11&param12=value12" +
        "&param13=value13&param14=value14&param15=value15&param16=value16&param17=value17&param18=value18&param19=value19&param20=value20#section1")] // Super long URI
    public void Sbom_Is_Successfully_Generated_Valid_URI(string namespaceBaseUri)
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = namespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.GeneratedSbomValidator.AssertSbomIsValid(this.ManifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSupplier, namespaceBaseUri);
    }

    [TestMethod]
    [DynamicData(nameof(GetPackageSupplierCases), DynamicDataSourceType.Method)]
    [DynamicData(nameof(GetPackageNameCases), DynamicDataSourceType.Method)]
    [DynamicData(nameof(GetPackageVersionCases), DynamicDataSourceType.Method)]
    public void Sbom_Is_Successfully_Generated_Valid_RequiredParams(string packageSupplier, string packageName, string packageVersion)
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = packageSupplier,
            PackageName = packageName,
            PackageVersion = packageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.GeneratedSbomValidator.AssertSbomIsValid(this.ManifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSupplier, NamespaceBaseUri);
    }

    private static IEnumerable<object[]> GetPackageSupplierCases()
    {
        yield return new object[] { "Test-\nMicrosoft", PackageName, PackageVersion };
        yield return new object[] { "Test\t-Microsoft", PackageName, PackageVersion };
        yield return new object[] { "Test  -     Microsoft   ", PackageName, PackageVersion };
        yield return new object[] { "Test - Mic\tro\nsoft", PackageName, PackageVersion };
    }

    private static IEnumerable<object[]> GetPackageNameCases()
    {
        yield return new object[] { PackageSupplier, "CoseSign\nTool", PackageVersion };
        yield return new object[] { PackageSupplier, "Cose\tSign\tTool", PackageVersion };
        yield return new object[] { PackageSupplier, "Cose     Sign   Tool   ", PackageVersion };
        yield return new object[] { PackageSupplier, "Cose    S\ti\ngn   \n Too\tl", PackageVersion };
    }

    private static IEnumerable<object[]> GetPackageVersionCases()
    {
        yield return new object[] { PackageSupplier, PackageName, "0.0\n.1" };
        yield return new object[] { PackageSupplier, PackageName, "0.0\t.1" };
        yield return new object[] { PackageSupplier, PackageName, "0.     0.    1" };
        yield return new object[] { PackageSupplier, PackageName, "0 .   \t 0 \n .1" };
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated_In_Specified_Location()
    {
        var manifestDirPath = Path.Combine(TemporaryDirectory, "sub-directory");
        Directory.CreateDirectory(manifestDirPath);
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            ManifestDirPath = manifestDirPath,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);

        this.ManifestPath = Path.Combine(manifestDirPath, "_manifest", this.SbomSpecificationDirectoryName, "manifest.spdx.json");
        this.GeneratedSbomValidator.AssertSbomIsValid(this.ManifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSupplier, NamespaceBaseUri);
    }

    [TestMethod]
    public void Sbom_Generation_Fails_With_NotFound_BuildDropPath()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = ".\\non-existent\\path",
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    [TestMethod]
    public void Sbom_Generation_Fails_With_NotFound_BuildComponentPath()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            BuildComponentPath = ".\\non-existent\\path",
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
        Assert.IsFalse(Directory.Exists(DefaultManifestDirectory));
    }

    [TestMethod]
    public void Sbom_Generation_Fails_With_NotFound_ExternalDocumentListFile()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            ExternalDocumentListFile = ".\\non-existent\\path",
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
        Assert.IsFalse(Directory.Exists(DefaultManifestDirectory));
    }

    [TestMethod]
    public void Sbom_Generation_Fails_With_NotFound_ManifestDirPath()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            ManifestDirPath = ".\\non-existent\\path",
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
        Assert.IsFalse(Directory.Exists(DefaultManifestDirectory));
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated_With_Component_Path()
    {
        // Let's generate a SBOM for the current assembly
        var sourceDirectory = Path.Combine(CurrentDirectory, "..", "..", "..");

        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            BuildComponentPath = sourceDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.GeneratedSbomValidator.AssertSbomIsValid(this.ManifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSupplier, NamespaceBaseUri, buildComponentPath: sourceDirectory);
    }

    [TestMethod]
    [DataRow("550e8400-e29b-41d4-a716-446655440000")] // Standard random GUID
    [DataRow("3F2504E0-4f89-11D3-9A0C-0305E82c3301")] // Mixed cases
    [DataRow("3F2504E04F8911D39A0C0305E82C3301")] // Guids without hyphens
    [DataRow("  3F2504E0-4F89-11D3-9A0C-0305E82C3301   ")] // Guids with trailing spaces
    public void Sbom_Is_Successfully_Generated_With_Unique_Namespace_Part_Defined(string uniqueNamespacePart)
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            NamespaceUriUniquePart = uniqueNamespacePart,
            BuildEngine = this.BuildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.GeneratedSbomValidator.AssertSbomIsValid(this.ManifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSupplier, NamespaceBaseUri, expectedNamespaceUriUniquePart: uniqueNamespacePart);
    }
}
