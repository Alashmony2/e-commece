import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDTO } from './dto/register.dto';
import { AuthFactoryService } from './factory/index';
import { LoginDTO } from './dto/login.dto';
import { ConfirmEmailDTO } from './dto/confirmEmail.dto';
import { ForgetPasswordDTO } from './dto/forgetPassword.dto';
import { ResetPasswordDTO } from './dto/resetPassword.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly authFactoryService: AuthFactoryService,
  ) {}

  @Post('/register')
  async register(@Body() registerDTO: RegisterDTO) {
    const customer = await this.authFactoryService.createCustomer(registerDTO);
    const createdCustomer = await this.authService.register(customer);
    return {
      message: 'Customer created successfully',
      success: true,
      data: createdCustomer,
    };
  }
  @Post('confirm-email')
  async confirmEmail(@Body() confirmEmailDTO: ConfirmEmailDTO) {
    const customer = await this.authService.confirmEmail(confirmEmailDTO);
    return {
      message: 'Email confirmed successfully',
      success: true,
      data: customer,
    };
  }

  @Post('login')
  async login(@Body() loginDTO: LoginDTO) {
    const token = await this.authService.login(loginDTO);
    return { message: 'Login successfully', success: true, data: { token } };
  }

  @Post('forget-password')
  async forgetPassword(@Body() forgetPasswordDTO: ForgetPasswordDTO) {
    const customer = await this.authService.forgetPassword(forgetPasswordDTO);
    return { message: 'otp send successfully', success: true, data: { customer } };
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordDTO: ResetPasswordDTO) {
    const token = await this.authService.resetPassword(resetPasswordDTO);
    return { message: 'Password reseted successfully', success: true, data: { token } };
  }

}
