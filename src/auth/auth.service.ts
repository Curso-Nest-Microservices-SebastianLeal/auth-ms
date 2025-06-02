import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto, LoginUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    try {
      const { email, name, password } = registerUserDto;

      const user = await this.user.findUnique({
        where: {
          email: email,
        },
      });
      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }
      const newUser = await this.user.create({
        data: {
          email: email,
          password: bcrypt.hashSync(password, 10), // Se encripta la password
          name: name,
        },
      });
      const { password: _, ...userWithoutPassword } = newUser;

      return {
        user: userWithoutPassword,
        token: await this.signJWT(userWithoutPassword),
      };
    } catch (err) {
      throw new RpcException({
        status: 400,
        message: err.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    try {
      const { email, password } = loginUserDto;

      const user = await this.user.findUnique({
        where: { email },
      });
      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid',
        });
      }
      const isPasswordValid = bcrypt.compareSync(password, user.password);
      if (!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid',
        });
      }
      const { password: _, ...rest } = user;
      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (err) {
      throw new RpcException({
        status: 400,
        message: err.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: 'Invalid token',
      });
    }
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
}
