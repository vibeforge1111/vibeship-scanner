import { task, logger } from "@trigger.dev/sdk/v3";

interface ScanPayload {
  scanId: string;
  repoUrl: string;
  branch: string;
}

interface ScanProgress {
  step: string;
  message: string;
}

interface ScanResult {
  status: string;
  score: number;
  grade: string;
  shipStatus: string;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  stack: {
    languages: string[];
    frameworks: string[];
    signature: string;
  };
  findings: Finding[];
  duration: number;
}

interface Finding {
  id: string;
  ruleId: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  location: {
    file: string;
    line: number;
    column?: number;
  };
  snippet?: {
    code: string;
    highlightLines: number[];
  };
  fix: {
    available: boolean;
    template?: string;
  };
  references?: string[];
}

export const scanRepository = task({
  id: "scan-repository",
  maxDuration: 300,
  run: async (payload: ScanPayload) => {
    const { scanId, repoUrl, branch } = payload;

    logger.info("Starting scan", { scanId, repoUrl, branch });

    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!supabaseUrl || !supabaseKey) {
      throw new Error("Missing Supabase credentials");
    }

    const updateProgress = async (step: string, message: string, percent: number) => {
      await fetch(`${supabaseUrl}/rest/v1/scan_progress`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": supabaseKey,
          "Authorization": `Bearer ${supabaseKey}`,
          "Prefer": "resolution=merge-duplicates"
        },
        body: JSON.stringify({
          scan_id: scanId,
          step,
          message,
          percent
        })
      });
    };

    const updateScan = async (data: Record<string, unknown>) => {
      await fetch(`${supabaseUrl}/rest/v1/scans?id=eq.${scanId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "apikey": supabaseKey,
          "Authorization": `Bearer ${supabaseKey}`
        },
        body: JSON.stringify(data)
      });
    };

    try {
      await updateScan({ status: "scanning" });
      await updateProgress("init", "Initializing scan...", 5);

      const flyAppName = process.env.FLY_SCANNER_APP || "vibeship-scanner";
      const flyToken = process.env.FLY_API_TOKEN;

      if (!flyToken) {
        throw new Error("Missing Fly.io API token");
      }

      await updateProgress("clone", "Cloning repository...", 15);

      const machineResponse = await fetch(
        `https://api.machines.dev/v1/apps/${flyAppName}/machines`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${flyToken}`
          },
          body: JSON.stringify({
            config: {
              image: `registry.fly.io/${flyAppName}:latest`,
              env: {
                REPO_URL: repoUrl,
                BRANCH: branch
              },
              auto_destroy: true,
              restart: {
                policy: "no"
              },
              guest: {
                cpu_kind: "shared",
                cpus: 1,
                memory_mb: 512
              }
            }
          })
        }
      );

      if (!machineResponse.ok) {
        const error = await machineResponse.text();
        logger.error("Failed to create scanner machine", { error });
        throw new Error(`Failed to create scanner: ${error}`);
      }

      const machine = await machineResponse.json();
      const machineId = machine.id;

      logger.info("Scanner machine created", { machineId });

      await updateProgress("sast", "Running code analysis...", 35);

      let scanComplete = false;
      let attempts = 0;
      const maxAttempts = 60;
      let result: ScanResult | null = null;

      while (!scanComplete && attempts < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, 5000));
        attempts++;

        const statusResponse = await fetch(
          `https://api.machines.dev/v1/apps/${flyAppName}/machines/${machineId}`,
          {
            headers: {
              "Authorization": `Bearer ${flyToken}`
            }
          }
        );

        if (statusResponse.ok) {
          const status = await statusResponse.json();

          if (status.state === "stopped" || status.state === "destroyed") {
            scanComplete = true;

            const logsResponse = await fetch(
              `https://api.machines.dev/v1/apps/${flyAppName}/machines/${machineId}/logs`,
              {
                headers: {
                  "Authorization": `Bearer ${flyToken}`
                }
              }
            );

            if (logsResponse.ok) {
              const logs = await logsResponse.text();
              const lines = logs.split("\n");

              for (const line of lines) {
                try {
                  const parsed = JSON.parse(line);
                  if (parsed.step === "complete" && parsed.result) {
                    result = parsed.result;
                  }
                } catch {
                  continue;
                }
              }
            }
          } else if (status.state === "started") {
            if (attempts < 15) {
              await updateProgress("deps", "Checking dependencies...", 55);
            } else if (attempts < 25) {
              await updateProgress("secrets", "Scanning for secrets...", 75);
            }
          }
        }
      }

      if (!result) {
        throw new Error("Scan did not complete successfully");
      }

      await updateProgress("score", "Calculating score...", 95);

      await updateScan({
        status: "complete",
        score: result.score,
        grade: result.grade,
        ship_status: result.shipStatus,
        summary: result.summary,
        stack: result.stack,
        findings: result.findings,
        duration_ms: result.duration,
        completed_at: new Date().toISOString()
      });

      await updateProgress("complete", "Scan complete!", 100);

      logger.info("Scan completed", { scanId, score: result.score });

      return {
        scanId,
        score: result.score,
        grade: result.grade,
        findingsCount: result.findings.length
      };

    } catch (error) {
      logger.error("Scan failed", { scanId, error });

      await updateScan({
        status: "failed",
        error: error instanceof Error ? error.message : "Unknown error"
      });

      throw error;
    }
  }
});
