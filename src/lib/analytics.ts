import * as amplitude from '@amplitude/analytics-browser';

const AMPLITUDE_API_KEY = 'ee065fa97abc603b7a93b1bdf831626d';

let initialized = false;

export function initAnalytics() {
  if (initialized || typeof window === 'undefined') return;

  amplitude.init(AMPLITUDE_API_KEY, {
    identityStorage: 'localStorage',
    defaultTracking: {
      sessions: false,
      pageViews: true,
      formInteractions: false,
      fileDownloads: false
    }
  });

  initialized = true;
}

// Page view tracking
export function trackPageView(pageName: string, properties?: Record<string, unknown>) {
  amplitude.track('Page Viewed', {
    page_name: pageName,
    url: typeof window !== 'undefined' ? window.location.href : '',
    ...properties
  });
}

// Scan events
export function trackScanStarted(repoUrl: string) {
  amplitude.track('Scan Started', {
    repo_url: repoUrl,
    repo_name: extractRepoName(repoUrl)
  });
}

export function trackScanCompleted(repoUrl: string, results: {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  duration?: number;
}) {
  amplitude.track('Scan Completed', {
    repo_url: repoUrl,
    repo_name: extractRepoName(repoUrl),
    total_findings: results.totalFindings,
    critical_count: results.criticalCount,
    high_count: results.highCount,
    medium_count: results.mediumCount,
    low_count: results.lowCount,
    duration_ms: results.duration
  });
}

export function trackScanFailed(repoUrl: string, error: string) {
  amplitude.track('Scan Failed', {
    repo_url: repoUrl,
    repo_name: extractRepoName(repoUrl),
    error_message: error
  });
}

export function trackScanResultsViewed(scanId: string, repoUrl: string, totalFindings: number) {
  amplitude.track('Scan Results Viewed', {
    scan_id: scanId,
    repo_url: repoUrl,
    repo_name: extractRepoName(repoUrl),
    total_findings: totalFindings
  });
}

// User actions
export function trackButtonClick(buttonName: string, properties?: Record<string, unknown>) {
  amplitude.track('Button Clicked', {
    button_name: buttonName,
    ...properties
  });
}

export function trackRecentScanClicked(repoUrl: string) {
  amplitude.track('Recent Scan Clicked', {
    repo_url: repoUrl,
    repo_name: extractRepoName(repoUrl)
  });
}

// Utility
function extractRepoName(repoUrl: string): string {
  try {
    const match = repoUrl.match(/github\.com\/([^\/]+\/[^\/]+)/);
    return match ? match[1] : repoUrl;
  } catch {
    return repoUrl;
  }
}

// Set user properties (for future use)
export function setUserProperties(properties: Record<string, unknown>) {
  const identify = new amplitude.Identify();
  Object.entries(properties).forEach(([key, value]) => {
    identify.set(key, value as string | number | boolean | string[]);
  });
  amplitude.identify(identify);
}

// Identify user (for logged-in users)
export function identifyUser(userId: string, properties?: Record<string, unknown>) {
  amplitude.setUserId(userId);
  if (properties) {
    setUserProperties(properties);
  }
}
