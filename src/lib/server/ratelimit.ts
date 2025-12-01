import { Redis } from '@upstash/redis';
import { Ratelimit } from '@upstash/ratelimit';
import { UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN } from '$env/static/private';

const redis = new Redis({
  url: UPSTASH_REDIS_REST_URL,
  token: UPSTASH_REDIS_REST_TOKEN,
});

export const scanRatelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(5, '1 h'),
  analytics: true,
  prefix: 'vibeship:scan',
});

export const apiRatelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(100, '1 m'),
  analytics: true,
  prefix: 'vibeship:api',
});

export async function checkRateLimit(
  identifier: string,
  type: 'scan' | 'api' = 'scan'
): Promise<{ success: boolean; remaining: number; reset: number }> {
  const limiter = type === 'scan' ? scanRatelimit : apiRatelimit;
  const { success, remaining, reset } = await limiter.limit(identifier);

  return {
    success,
    remaining,
    reset,
  };
}

export async function getRateLimitStatus(
  identifier: string,
  type: 'scan' | 'api' = 'scan'
): Promise<{ remaining: number; reset: number }> {
  const limiter = type === 'scan' ? scanRatelimit : apiRatelimit;
  const { remaining, reset } = await limiter.limit(identifier);

  return { remaining, reset };
}
