/** Relay origin for diagnostics. Paths and queries may contain credentials. */
export function endpointOrigin(endpoint: string): string {
  try {
    return new URL(endpoint).origin;
  } catch {
    return 'configured endpoint';
  }
}
