// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom;

using System.Diagnostics.Tracing;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Contracts;

public class GenerationService : IHostedService
{
    private readonly ISBOMGenerator generator;
    private readonly IHostApplicationLifetime hostApplicationLifetime;

    public GenerationService(ISBOMGenerator generator, IHostApplicationLifetime hostApplicationLifetime)
    {
        this.generator = generator;
        this.hostApplicationLifetime = hostApplicationLifetime;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var result = await this.generator.GenerateSbomAsync(
            rootPath: "C:\\Users\\gustavoca\\Repos\\ES.ArtifactServices\\VPackLite\\output\\bin\\DebugWithCacheNoFallback\\VPack\\net48\\CoseSignTool",
            metadata: new SBOMMetadata
            {
                PackageSupplier = "Contoso",
                PackageName = "CoseSignToolSbomTest",
                PackageVersion = "1.0.0",
            },
            componentPath: null,
            runtimeConfiguration: new RuntimeConfiguration
            {
                NamespaceUriBase = "http://spdx.org/spdxdocs/Test",
                DeleteManifestDirectoryIfPresent = true,
                Verbosity = EventLevel.Warning,
            },
            specifications: null);
            /*,
            // componentPath: ,
            metadata: new SBOMMetadata(),
            runtimeConfiguration: configuration,
            manifestDirPath: sbomOutputPath*/

        this.hostApplicationLifetime.StopApplication();
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
