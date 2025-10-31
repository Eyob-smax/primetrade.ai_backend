import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({
    origin: [
      'http://localhost:5173',
      'https://primetradeaibackend-production.up.railway.app/',
    ],
    credentials: true,
  });
  app.use(cookieParser());

  await app.listen(process.env.PORT ?? 9000);
}
bootstrap();
