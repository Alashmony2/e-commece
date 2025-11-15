import { Module } from '@nestjs/common';
import { CategoryService } from './category.service';
import { CategoryController } from './category.controller';
import { Category, CategoryRepository, categorySchema } from '@models/index';
import { MongooseModule } from '@nestjs/mongoose';
import { CategoryFactoryService } from './factory';
import { JwtService } from '@nestjs/jwt';

@Module({
  imports:[MongooseModule.forFeature([{name:Category.name,schema:categorySchema}])],
  controllers: [CategoryController],
  providers: [CategoryService,CategoryRepository,CategoryFactoryService,JwtService],
})
export class CategoryModule {}
