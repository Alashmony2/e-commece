import { Injectable } from '@nestjs/common';
import { RegisterDTO } from './dto/register.dto';

@Injectable()
export class AuthService {
  register(registerDTO: RegisterDTO) {
    return 'This action adds a new auth';
  }

  
}
