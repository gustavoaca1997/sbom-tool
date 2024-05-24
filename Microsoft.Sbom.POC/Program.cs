// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom;

using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Extensions.DependencyInjection;

internal class Program
{
    public static async Task Main(string[] args) =>
        await Host.CreateDefaultBuilder(args)
            .ConfigureServices((host, services) =>
                services
                .AddHostedService<GenerationService>()
                .AddSbomTool())
            .RunConsoleAsync(x => x.SuppressStatusMessages = true);
}
