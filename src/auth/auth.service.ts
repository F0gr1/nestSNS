import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string) {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('ユーザーが見つかりません');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('パスワードが正しくありません');
    }

    const { password: _, ...result } = user;
    return result;
  }

  async login(user: any) {
    const payload = { email: user.email, sub: user.id };
    return {
      user,
      access_token: this.jwtService.sign(payload),
    };
  }

  async register(userData: {
    email: string;
    password: string;
    username: string;
  }) {
    const existingUser = await this.usersService.findByEmail(userData.email);
    if (existingUser) {
      throw new UnauthorizedException(
        'このメールアドレスは既に使用されています',
      );
    }

    const user = await this.usersService.create(userData);
    return this.login(user);
  }
}
