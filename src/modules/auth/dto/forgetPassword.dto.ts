import { IsEmail, IsNotEmpty } from 'class-validator';

export class ForgetPasswordDTO {
  @IsNotEmpty()
  @IsEmail()
  email: string;
}
