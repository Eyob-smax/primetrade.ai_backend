import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { verify } from '../utils/authUtil.js';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from 'jsonwebtoken';

type UserRole = 'ADMIN' | 'USER';

interface RolePayload extends JwtPayload {
  role: UserRole;
}

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly config: ConfigService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      'roles',
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const token = request.cookies?.['access_token'];
    const secret =
      this.config.get<string>('JWT_ACCESS_SECRET') ||
      process.env.JWT_ACCESS_SECRET;

    if (!token)
      throw new UnauthorizedException('Authentication token not found.');
    if (!secret) throw new UnauthorizedException('JWT secret not configured.');

    let decoded: RolePayload;
    try {
      decoded = verify(token, secret) as RolePayload;
    } catch {
      throw new UnauthorizedException(
        'Invalid or expired authentication token.',
      );
    }

    const userRole = decoded.role;
    if (!userRole) {
      throw new UnauthorizedException('Token missing role information.');
    }

    const hasPermission = requiredRoles.includes(userRole);
    if (!hasPermission) {
      throw new ForbiddenException(
        `Role "${userRole}" is not authorized. You should have a role ${JSON.stringify(requiredRoles)} to access this route!`,
      );
    }

    return true;
  }
}
