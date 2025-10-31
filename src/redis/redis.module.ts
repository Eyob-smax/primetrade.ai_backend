import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient } from 'redis';

@Global()
@Module({
  exports: ['REDIS_CLIENT'],
  providers: [
    {
      provide: 'REDIS_CLIENT',
      inject: [ConfigService],
      useFactory: async (config: ConfigService) => {
        const redisUrl =
          config.get<string>('REDIS_URL') || process.env.REDIS_URL;
        if (!redisUrl) throw new Error('REDIS_URL is not defined in env');

        const redisClient = createClient({ url: redisUrl });
        redisClient.on('error', (err) =>
          console.error('Redis Client Error', err),
        );

        let connected = false;
        const maxRetries = 5;
        let attempt = 0;

        while (!connected && attempt < maxRetries) {
          try {
            await redisClient.connect();
            connected = true;
            console.log('Connected to Redis');
          } catch (err: any) {
            attempt++;
            console.error(
              `Redis connection failed (attempt ${attempt}): ${err.message}`,
            );
            await new Promise((res) => setTimeout(res, 3000));
          }
        }

        if (!connected) {
          throw new Error("Can't connect to REDIS after multiple attempts!");
        }

        return redisClient;
      },
    },
  ],
})
export class RedisModule {}
