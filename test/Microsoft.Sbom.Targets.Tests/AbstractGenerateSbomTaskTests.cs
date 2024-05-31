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

/// <summary>
/// Base class for testing SBOM generation through the GenerateSbomTask.
/// </summary>
[TestClass]
public abstract class AbstractGenerateSbomTaskTests
{
    internal SbomSpecification SbomSpecification;

    private static readonly string CurrentDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    private static readonly string DefaultManifestDirectory = Path.Combine(CurrentDirectory, "_manifest");
    private static readonly string TemporaryDirectory = Path.Combine(CurrentDirectory, "_temp");
    private const string PackageSuplier = "Test-Microsoft";
    private const string PackageName = "CoseSignTool";
    private const string PackageVersion = "0.0.1";
    private const string NamespaceBaseUri = "https://base0.uri";

    private Mock<IBuildEngine> buildEngine;
    private List<BuildErrorEventArgs> errors;
    private string manifestPath;
    private GeneratedSbomValidator generatedSbomValidator;

    private string SbomSpecificationDirectoryName => $"{this.SbomSpecification.Name}_{this.SbomSpecification.Version}";

    [TestInitialize]
    public void Startup()
    {
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
        this.generatedSbomValidator = new(this.SbomSpecification);
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
            BuildEngine = this.buildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
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
            BuildEngine = this.buildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);

        this.manifestPath = Path.Combine(manifestDirPath, "_manifest", this.SbomSpecificationDirectoryName, "manifest.spdx.json");
        this.generatedSbomValidator.AssertSbomIsValid(this.manifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSuplier, NamespaceBaseUri);
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
            BuildEngine = this.buildEngine.Object,
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
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object,
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
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object,
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
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object,
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
            PackageSupplier = PackageSuplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildEngine = this.buildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.generatedSbomValidator.AssertSbomIsValid(this.manifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSuplier, NamespaceBaseUri, buildComponentPath: sourceDirectory);
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
            BuildEngine = this.buildEngine.Object,
            ManifestInfo = this.SbomSpecification.ToString(),
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
        this.generatedSbomValidator.AssertSbomIsValid(this.manifestPath, CurrentDirectory, PackageName, PackageVersion, PackageSuplier, NamespaceBaseUri, expectedNamespaceUriUniquePart: uniqueNamespacePart);
    }
}
