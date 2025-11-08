import { Controller, Get, Request, UseGuards } from '@nestjs/common';
import { CustomerService } from './customer.service';
import { AuthGuard } from '@common/guards';

@Controller('customer')
export class CustomerController {
  constructor(private readonly customerService: CustomerService) {}

  @Get()
  @UseGuards(AuthGuard)
  getProfile(@Request() request: any) {
    return {
      message: 'Profile fetched successfully',
      success: true,
      data: {user:request.user},
    };
  }
}
