import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { verify } from '../utils/authUtil.js';
import { JwtPayload } from 'jsonwebtoken';

interface AuthUser extends JwtPayload {
  id: number;
  username: string;
  role: string;
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const token = request.cookies?.['access_token'];
    if (!token) {
      throw new UnauthorizedException('ACCESS_TOKEN_NOT_FOUND');
    }

    const access_token_secret = this.config.get<string>('JWT_ACCESS_SECRET');
    if (!access_token_secret) {
      throw new UnauthorizedException('JWT_TOKEN_NOT_CONFIGURED');
    }

    try {
      const decoded = verify(token, access_token_secret) as AuthUser;

      if (!decoded || !decoded.id) {
        throw new UnauthorizedException('INVALID_ACCESS_TOKEN');
      }

      request.user = decoded;
      return true;
    } catch (err) {
      console.log(err);
      if (err.name === 'TokenExpiredError') {
        throw new UnauthorizedException('ACCESS_TOKEN_EXPIRED');
      }
      throw new UnauthorizedException(
        'Invalid or expired authentication token.',
      );
    }
  }
}
