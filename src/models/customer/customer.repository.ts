import { Model } from 'mongoose';
import { AbstractRepository } from './../abstract.repository';
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Customer } from './customer.schema';

@Injectable()
export class CustomerRepository extends AbstractRepository<Customer> {
  constructor(@InjectModel(Customer.name) private readonly customerModel: Model<Customer>) {
    super(customerModel);
  }
}
