using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Build.Framework;
using Microsoft.Sbom.Targets;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Targets.Tests;

[TestClass]
public class GenerateSbomTaskTests
{
    private Mock<IBuildEngine> buildEngine;
    private List<BuildErrorEventArgs> errors;

    [TestInitialize]
    public void Startup()
    {
        buildEngine = new Mock<IBuildEngine>();
        errors = new List<BuildErrorEventArgs>();
        buildEngine.Setup(x => x.LogErrorEvent(It.IsAny<BuildErrorEventArgs>())).Callback<BuildErrorEventArgs>(e => errors.Add(e));
    }

    [TestMethod]
    public void Sbom_Is_Successfully_Generated()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = "C:\\Users\\gustavoca\\Repos\\ES.ArtifactServices\\VPackLite\\output\\bin\\DebugWithCacheNoFallback\\VPack\\net48\\CoseSignTool",
            BuildComponentPath = null,
            PackageSupplier = "Microsoft",
            PackageName = "CoseSignTool",
            PackageVersion = "1.0.0",
            NamespaceBaseUri = "https://base.uri",
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsTrue(result);
    }
}
