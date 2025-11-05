import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserMongoModule } from '@shared/index';
import { AuthFactoryService } from './factory';

@Module({
  imports: [UserMongoModule],
  controllers: [AuthController],
  providers: [AuthService,AuthFactoryService],
})
export class AuthModule {}
