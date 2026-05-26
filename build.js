import { build as viteBuild } from "vite";
import { build as esbuildBuild } from "esbuild";

console.log("🚀 Starting Unified cross-platform programmatic build...");

async function run() {
  try {
    console.log("\n📦 Phase 1: Building Frontend static files (Vite programmatically)...");
    await viteBuild();

    console.log("\n⚙️ Phase 2: Bundling Backend TS Server (esbuild programmatically)...");
    await esbuildBuild({
      entryPoints: ["server.ts"],
      bundle: true,
      platform: "node",
      format: "cjs",
      packages: "external",
      sourcemap: true,
      outfile: "dist/server.cjs"
    });

    console.log("\n✅ Programmatic build pipeline completed successfully! Ready for production.");
  } catch (error) {
    console.error("\n❌ Build pipeline failed:", error);
    process.exit(1);
  }
}

run();
