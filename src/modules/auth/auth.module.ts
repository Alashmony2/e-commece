import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import {
  Customer,
  CustomerRepository,
  customerSchema,
  User,
  userSchema,
} from 'src/models';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: User.name,
        schema: userSchema,
        discriminators: [{ name: Customer.name, schema: customerSchema }],
      },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, CustomerRepository],
})
export class AuthModule {}
