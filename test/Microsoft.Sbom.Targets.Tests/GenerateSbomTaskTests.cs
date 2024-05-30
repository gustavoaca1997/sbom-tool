using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Build.Framework;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions.DependencyInjection;
using Microsoft.Sbom.Targets;
using Microsoft.Sbom.Targets.Tests.Utility;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Newtonsoft.Json;

namespace Microsoft.Sbom.Targets.Tests;

[TestClass]
public class GenerateSbomTaskTests
{
    private static readonly string CurrentDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    private static readonly string DefaultManifestDirectory = Path.Combine(CurrentDirectory, "_manifest");
    private static readonly string TemporaryDirectory = Path.Combine(CurrentDirectory, "_temp");
    private const string PackageSuplier = "Test-Microsoft";
    private const string PackageName = "CoseSignTool";
    private const string PackageVersion = "0.0.1";
    private const string NamespaceBaseUri = "https://base0.uri";

    private Mock<IBuildEngine> buildEngine;
    private List<BuildErrorEventArgs> errors;
    private ISBOMValidator sbomValidator;
    private string manifestPath;
    private SbomSpecification sbomSpecification;
    private GeneratedSbomValidator generatedSbomValidator;

    private string SbomSpecificationDirectoryName => $"{this.sbomSpecification.Name}_{this.sbomSpecification.Version}";

    public GenerateSbomTaskTests()
    {
        this.sbomSpecification = Constants.SPDX22Specification;
    }

    [TestInitialize]
    public void Startup()
    {
        var host = Host.CreateDefaultBuilder()
            .ConfigureServices((host, services) =>
                services
                .AddSbomTool())
            .Build();
        this.sbomValidator = host.Services.GetRequiredService<ISBOMValidator>();

        // Setup the build engine
        this.buildEngine = new Mock<IBuildEngine>();
        this.errors = new List<BuildErrorEventArgs>();
        this.buildEngine.Setup(x => x.LogErrorEvent(It.IsAny<BuildErrorEventArgs>())).Callback<BuildErrorEventArgs>(e => errors.Add(e));

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

        this.manifestPath = Path.Combine(DefaultManifestDirectory, this.SbomSpecificationDirectoryName, "manifest.spdx.json");
        this.generatedSbomValidator = new(this.sbomSpecification);
    }

    [TestCleanup]
    public void Cleanup()
    {
#pragma warning disable VSTHRD002 // Avoid problematic synchronous waits
        if (File.Exists(this.manifestPath))
        {
            Assert.IsTrue(this.sbomValidator.ValidateSbomAsync(
                CurrentDirectory,
                TemporaryDirectory,
                null,
                manifestDirPath: Path.Combine(this.manifestPath, "..", "..")).GetAwaiter().GetResult().IsSuccess);
        }
#pragma warning restore VSTHRD002 // Avoid problematic synchronous waits
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.generatedSbomValidator.AssertSbomIsValid(this.manifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSuplier, NamespaceBaseUri);
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
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);

        this.manifestPath = Path.Combine(manifestDirPath, "_manifest", this.SbomSpecificationDirectoryName, "manifest.spdx.json");
        Assert.IsTrue(File.Exists(manifestPath));

        // Read and parse the manifest
        var manifestContent = File.ReadAllText(this.manifestPath);
        var manifest = JsonConvert.DeserializeObject<dynamic>(manifestContent);

        // Check the manifest has expected values
        var filesValue = manifest["files"];
        Assert.IsNotNull(filesValue);
        Assert.IsTrue(filesValue.Count > 0);

        var packagesValue = manifest["packages"];
        Assert.IsNotNull(packagesValue);
        Assert.IsTrue(packagesValue.Count == 1);

        var nameValue = manifest["name"];
        Assert.IsNotNull(nameValue);
        Assert.AreEqual($"{PackageName} {PackageVersion}", (string)nameValue);

        var creatorsValue = manifest["creationInfo"]["creators"];
        Assert.IsNotNull(creatorsValue);
        Assert.IsTrue(creatorsValue.Count > 0);
        Assert.IsTrue(((string)creatorsValue[0]).Contains(PackageSuplier));

        string namespaceValue = manifest["documentNamespace"];
        Assert.IsNotNull(namespaceValue);
        Assert.IsTrue(namespaceValue.Contains($"{NamespaceBaseUri}/{PackageName}/{PackageVersion}"));
    }

    [TestMethod]
    public void Sbom_Generation_Fails_With_NotFound_BuildDropPath()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = ".\\non-existent\\path",
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object
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
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object
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
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object
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
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object
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
        var sourceDirectory = Path.Combine(CurrentDirectory, "..\\..\\..");

        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            BuildComponentPath = sourceDirectory,
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        Assert.IsTrue(File.Exists(manifestPath));

        // Read and parse the manifest
        var manifestContent = File.ReadAllText(manifestPath);
        var manifest = JsonConvert.DeserializeObject<dynamic>(manifestContent);

        // Check the manifest has expected values
        var filesValue = manifest["files"];
        Assert.IsNotNull(filesValue);
        Assert.IsTrue(filesValue.Count > 0);

        var packagesValue = manifest["packages"];
        Assert.IsNotNull(packagesValue);
        Assert.IsTrue(packagesValue.Count > 1);

        var nameValue = manifest["name"];
        Assert.IsNotNull(nameValue);
        Assert.AreEqual($"{PackageName} {PackageVersion}", (string)nameValue);

        var creatorsValue = manifest["creationInfo"]["creators"];
        Assert.IsNotNull(creatorsValue);
        Assert.IsTrue(creatorsValue.Count > 0);
        Assert.IsTrue(((string)creatorsValue[0]).Contains(PackageSuplier));

        string namespaceValue = manifest["documentNamespace"];
        Assert.IsNotNull(namespaceValue);
        Assert.IsTrue(namespaceValue.Contains($"{NamespaceBaseUri}/{PackageName}/{PackageVersion}"));
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated_With_Unique_Namespace_Part_Defined()
    {
        var uniqueNamespacePart = Guid.NewGuid().ToString();
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            NamespaceUriUniquePart = uniqueNamespacePart,
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        Assert.IsTrue(File.Exists(manifestPath));

        // Read and parse the manifest
        var manifestContent = File.ReadAllText(manifestPath);
        var manifest = JsonConvert.DeserializeObject<dynamic>(manifestContent);

        // Check the manifest has expected values
        var filesValue = manifest["files"];
        Assert.IsNotNull(filesValue);
        Assert.IsTrue(filesValue.Count > 0);

        var packagesValue = manifest["packages"];
        Assert.IsNotNull(packagesValue);
        Assert.IsTrue(packagesValue.Count == 1);

        var nameValue = manifest["name"];
        Assert.IsNotNull(nameValue);
        Assert.AreEqual($"{PackageName} {PackageVersion}", (string)nameValue);

        var creatorsValue = manifest["creationInfo"]["creators"];
        Assert.IsNotNull(creatorsValue);
        Assert.IsTrue(creatorsValue.Count > 0);
        Assert.IsTrue(((string)creatorsValue[0]).Contains(PackageSuplier));

        string namespaceValue = manifest["documentNamespace"];
        Assert.IsNotNull(namespaceValue);
        Assert.AreEqual($"{NamespaceBaseUri}/{PackageName}/{PackageVersion}/{uniqueNamespacePart}", namespaceValue);
    }
}
