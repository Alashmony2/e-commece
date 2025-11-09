import { Roles } from '@common/decorators';
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const roles = this.reflector.getAllAndMerge(Roles, [
      context.getHandler(),
      context.getClass(),
    ]);
    const publicVal = this.reflector.get('PUBLIC', context.getHandler());
    if (publicVal) return true;
    if (!roles.includes(request.user.role))
      throw new UnauthorizedException('Not Allowed');
    return true;
  }
}
