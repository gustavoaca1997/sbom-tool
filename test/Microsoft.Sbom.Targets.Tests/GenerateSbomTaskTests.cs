using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Build.Framework;
using Microsoft.Sbom.Targets;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Newtonsoft.Json;

namespace Microsoft.Sbom.Targets.Tests;

[TestClass]
public class GenerateSbomTaskTests
{
    private static readonly string CurrentDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    private static readonly string ManifestDirectory = Path.Combine(CurrentDirectory, "_manifest");
    private static readonly string TemporaryDirectory = Path.Combine(CurrentDirectory, "_temp");
    private static readonly string ManifestPath = Path.Combine(ManifestDirectory, "spdx_2.2", "manifest.spdx.json");
    private const string PackageSuplier = "Test-Microsoft";
    private const string PackageName = "CoseSignTool";
    private const string PackageVersion = "0.0.1";
    private const string NamespaceBaseUri = "https://base0.uri";

    private Mock<IBuildEngine> buildEngine;
    private List<BuildErrorEventArgs> errors;

    [TestInitialize]
    public void Startup()
    {
        // Setup the build engine
        buildEngine = new Mock<IBuildEngine>();
        errors = new List<BuildErrorEventArgs>();
        buildEngine.Setup(x => x.LogErrorEvent(It.IsAny<BuildErrorEventArgs>())).Callback<BuildErrorEventArgs>(e => errors.Add(e));

        // Clean up the manifest directory
        if (Directory.Exists(ManifestDirectory))
        {
            Directory.Delete(ManifestDirectory, true);
        }
    }

    [TestCleanup]
    public void Cleanup()
    {
        // Clean up the manifest directory
        if (Directory.Exists(TemporaryDirectory))
        {
            Directory.Delete(TemporaryDirectory, true);
        }
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
        Assert.IsTrue(File.Exists(ManifestPath));

        // Read and parse the manifest
        var manifestContent = File.ReadAllText(ManifestPath);
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

        var manifestPath = Path.Combine(manifestDirPath, "_manifest", "spdx_2.2", "manifest.spdx.json");
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
        Assert.IsFalse(Directory.Exists(ManifestDirectory));
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
        Assert.IsFalse(Directory.Exists(ManifestDirectory));
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
        Assert.IsFalse(Directory.Exists(ManifestDirectory));
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
        Assert.IsTrue(File.Exists(ManifestPath));

        // Read and parse the manifest
        var manifestContent = File.ReadAllText(ManifestPath);
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
        Assert.IsTrue(File.Exists(ManifestPath));

        // Read and parse the manifest
        var manifestContent = File.ReadAllText(ManifestPath);
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
