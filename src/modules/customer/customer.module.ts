import { Module } from '@nestjs/common';
import { CustomerService } from './customer.service';
import { CustomerController } from './customer.controller';
import { JwtService } from '@nestjs/jwt';
import { UserMongoModule } from '@shared/index';

@Module({
  imports: [UserMongoModule],
  controllers: [CustomerController],
  providers: [CustomerService,JwtService],
})
export class CustomerModule {}
