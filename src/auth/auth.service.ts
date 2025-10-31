import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  InternalServerErrorException,
  ConflictException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DatabaseService } from '../database/database.service.js';
import { CreateAuthDto } from './dto/auth.dto';
import { CreateRegisterDto } from './dto/create-register.dto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { mapPrismaErrorToHttp } from '../common/utils/handleDbError.js';
import {
  ACCESS_TOKEN_EX_STR,
  REFRESH_TOKEN_EX_NUM,
} from '../common/constants/constants.js';
import { Request } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private readonly databaseService: DatabaseService,
    private readonly config: ConfigService,
  ) {}

  async login(authDto: CreateAuthDto) {
    const { email, password } = authDto;

    if (!email || !password) {
      throw new BadRequestException('Missing required fields');
    }

    try {
      const user = await this.databaseService.user.findUnique({
        where: { email },
      });

      if (!user)
        throw new UnauthorizedException(
          'User not found in our DB: invalid email or password!',
        );

      const isPasswordValid = await bcrypt.compare(
        password,
        user.hashed_password,
      );
      if (!isPasswordValid) throw new UnauthorizedException('Invalid password');

      const accessSecret =
        this.config.get<string>('JWT_ACCESS_SECRET') ||
        process.env.JWT_ACCESS_SECRET;
      const refreshSecret =
        this.config.get<string>('JWT_REFRESH_SECRET') ||
        process.env.JWT_REFRESH_SECRET;
      if (!accessSecret || !refreshSecret)
        throw new InternalServerErrorException('JWT secrets not configured');

      const payload = {
        id: user.user_id,
        name: user.name,
        role: user.role,
      };

      const accessToken = jwt.sign(payload, accessSecret, {
        expiresIn: ACCESS_TOKEN_EX_STR,
      });

      const refreshToken = jwt.sign(payload, refreshSecret, {
        expiresIn: ACCESS_TOKEN_EX_STR,
      });

      const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
      const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EX_NUM);

      await this.databaseService.refreshToken.create({
        data: {
          token: hashedRefreshToken,
          expires_at: expiresAt,
          user_id: user.user_id,
        },
      });

      return {
        accessToken,
        refreshToken,
        user: {
          id: user.user_id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      };
    } catch (err) {
      console.error('Login error:', err);
      throw mapPrismaErrorToHttp(err);
    }
  }

  async refreshTokens(refreshToken: string) {
    if (!refreshToken)
      throw new UnauthorizedException('No refresh token found');

    try {
      const refreshSecret =
        this.config.get<string>('JWT_REFRESH_SECRET') ||
        process.env.JWT_REFRESH_SECRET;
      if (!refreshSecret) {
        throw new InternalServerErrorException(
          'Jrt refresh token not configured correctly!',
        );
      }
      const decoded = jwt.verify(refreshToken, refreshSecret) as any;

      const userTokens = await this.databaseService.refreshToken.findMany({
        where: { user_id: decoded.id, revoked: false },
      });

      //?I use any to exit out of the promise as soon as I get valid token.
      const validToken = await Promise.any(
        userTokens.map(async (t) => {
          const match = await bcrypt.compare(refreshToken, t.token);
          if (match && t.expires_at > new Date()) return t;
          return null;
        }),
      ).catch(() => null);

      if (!validToken)
        throw new UnauthorizedException(
          'Invalid or expired token, please login again',
        );

      await this.databaseService.refreshToken.update({
        where: { token_id: validToken.token_id },
        data: { revoked: true },
      });
      const user = await this.databaseService.user.findUnique({
        where: { user_id: decoded.id },
      });
      if (!user) {
        throw new UnauthorizedException(
          "We couldn't find any authorized user eith the given token. the use may not exist",
        );
      }
      const accessSecret =
        this.config.get<string>('JWT_ACCESS_SECRET') ||
        process.env.JWT_ACCESS_SECRET;
      if (!accessSecret) {
        throw new InternalServerErrorException(
          'Jwt access secret key is not configured',
        );
      }
      const payload = {
        id: user?.user_id,
        name: user.name,
        role: user.role,
      };

      const newAccessToken = jwt.sign(payload, accessSecret, {
        expiresIn: ACCESS_TOKEN_EX_STR,
      });
      const newRefreshToken = jwt.sign(payload, refreshSecret, {
        expiresIn: REFRESH_TOKEN_EX_NUM,
      });
      const hashedNewToken = await bcrypt.hash(newRefreshToken, 10);

      await this.databaseService.refreshToken.create({
        data: {
          user_id: user.user_id,
          token: hashedNewToken,
          expires_at: new Date(Date.now() + REFRESH_TOKEN_EX_NUM),
        },
      });

      return { newAccessToken, newRefreshToken };
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        throw new UnauthorizedException('REFRESH_TOKEN_EXPIRED');
      }
      throw mapPrismaErrorToHttp(err);
    }
  }

  async logout(refreshToken: string) {
    try {
      if (refreshToken) {
        const decoded = jwt.decode(refreshToken) as any;
        await this.databaseService.refreshToken.updateMany({
          where: { user_id: decoded?.id },
          data: { revoked: true },
        });
      }

      return { message: 'Logout successful' };
    } catch (error) {
      throw mapPrismaErrorToHttp(error);
    }
  }
  async register(createRegisterDto: CreateRegisterDto) {
    try {
      const { email, password, name, role } = createRegisterDto;

      if (!email || !password || !name) {
        throw new BadRequestException('Missing required fields');
      }

      const existingUser = await this.databaseService.user.findUnique({
        where: { email },
      });

      if (existingUser) {
        throw new ConflictException('Email already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await this.databaseService.user.create({
        data: {
          email,
          name,
          role: role,
          hashed_password: hashedPassword,
        },
      });

      const accessSecret =
        this.config.get<string>('JWT_ACCESS_SECRET') ||
        process.env.JWT_ACCESS_SECRET;
      const refreshSecret =
        this.config.get<string>('JWT_REFRESH_SECRET') ||
        process.env.JWT_REFRESH_SECRET;

      if (!accessSecret || !refreshSecret) {
        throw new InternalServerErrorException(
          'Jwt not coonfigured successfully!',
        );
      }

      const payload = {
        id: user.user_id,
        name: user.name,
        role: user.role,
      };

      const accessToken = jwt.sign(payload, accessSecret, {
        expiresIn: ACCESS_TOKEN_EX_STR,
      });

      const refreshToken = jwt.sign(payload, refreshSecret, {
        expiresIn: ACCESS_TOKEN_EX_STR,
      });

      const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
      const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EX_NUM);

      await this.databaseService.refreshToken.create({
        data: {
          token: hashedRefreshToken,
          expires_at: expiresAt,
          user_id: user.user_id,
        },
      });

      if (!accessToken || !refreshToken || !user) {
        throw new InternalServerErrorException(
          'Registration failed, please try again.',
        );
      }

      return {
        accessToken,
        refreshToken,
        user: {
          id: user.user_id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      };
    } catch (error) {
      console.error('Registration error:', error);
      throw mapPrismaErrorToHttp(error);
    }
  }

  async getCurrentUser(req: Request) {
    try {
      const token = req.cookies['access_token'];
      if (!token) {
        throw new UnauthorizedException('No access token found');
      }

      const decoded = jwt.verify(
        token,
        this.config.get<string>('JWT_ACCESS_SECRET') ||
          (process.env.JWT_ACCESS_SECRET as string),
      ) as {
        id: string;
        name: string;
        role: string;
        email?: string;
      };
      if (!decoded) {
        throw new UnauthorizedException('Invalid access token');
      }
      return {
        id: decoded.id,
        name: decoded.name,
        role: decoded.role,
        email: decoded.email,
      };
    } catch (error) {
      throw new BadRequestException('Could not retrieve user information');
    }
  }
}
