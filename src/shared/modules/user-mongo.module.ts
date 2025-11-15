import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import {
  Admin,
  AdminRepository,
  adminSchema,
  Customer,
  CustomerRepository,
  customerSchema,
  Seller,
  SellerRepository,
  sellerSchema,
  User,
  UserRepository,
  userSchema,
} from 'src/models';

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: User.name,
        schema: userSchema,
        discriminators: [
          { name: Seller.name, schema: sellerSchema },
          { name: Admin.name, schema: adminSchema },
          { name: Customer.name, schema: customerSchema },
        ],
      },
    ]),
  ],
  providers: [
    SellerRepository,
    AdminRepository,
    CustomerRepository,
    UserRepository,
  ],
  exports: [
    SellerRepository,
    AdminRepository,
    CustomerRepository,
    UserRepository,
  ],
})
export class UserMongoModule {}
