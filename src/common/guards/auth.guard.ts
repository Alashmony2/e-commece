import { PUBLIC } from '@common/decorators';
import { CustomerRepository } from '@models/index';
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly customerRepository: CustomerRepository,
    private readonly reflector: Reflector,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const publicVal = this.reflector.get(PUBLIC, context.getHandler());
    if (publicVal) return true;
    const request = context.switchToHttp().getRequest();
    const { authorization } = request.headers;
    const payload = this.jwtService.verify<{
      _id: string;
      role: string;
      email: string;
    }>(authorization, {
      secret: this.configService.get('access').jwt_secret,
    });
    const customerExist = await this.customerRepository.getOne({
      _id: payload._id,
    });
    if (!customerExist) throw new NotFoundException('Customer not found');
    request.user = customerExist;
    return true;
  }
}
