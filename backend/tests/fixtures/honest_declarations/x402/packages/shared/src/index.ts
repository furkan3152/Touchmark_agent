export function decodePaymentHeader(header: string): unknown {
  return JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
}
export const DEFAULT_TIMEOUT_SECONDS = 60;
