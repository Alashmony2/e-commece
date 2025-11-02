import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './modules/auth/auth.module';
import { BrandModule } from './modules/brand/brand.module';
import { ProductModule } from './modules/product/product.module';
import { CategoryModule } from './modules/category/category.module';

@Module({
    imports: [AuthModule, BrandModule, ProductModule, CategoryModule],
    controllers: [AppController],
    providers: [AppService],
})
export class AppModule {}
