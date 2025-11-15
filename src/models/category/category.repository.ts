import { Model } from 'mongoose';
import { AbstractRepository } from './../abstract.repository';
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Category } from './category.schema';

@Injectable()
export class CategoryRepository extends AbstractRepository<Category> {
  constructor(
    @InjectModel(Category.name) private readonly categoryModel: Model<Category>,
  ) {
    super(categoryModel);
  }
}
