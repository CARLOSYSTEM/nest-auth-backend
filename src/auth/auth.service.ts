import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterUserDto } 
from './dto/index';

import { JwtPayload } from './interface/jwt';
import { User } from './entities/user.entity';
import { LoginResponse } from './interface/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService

  ) {

  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    // return user.save();
    try {
      const { password, ...user_data } = createUserDto;
      // ! encriptar password
      const new_user = new this.userModel({
        password: bcrypt.hashSync(password, 10),
        ...user_data
      });

      // ! guardar el usuario
      await new_user.save();

      const { password: _, ...user } = new_user.toJSON();

      return user as User;

    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`El correo ya existe ${createUserDto.email}, validar!`);
      }

      throw new InternalServerErrorException('Error al crear el usuario');
    }

    // ! encriptar password


    // ! guardar el usuario


    // ! generar el jwt

  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException('El correo no existe');
    }

    if (!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('El password no es valido');
    }

    const { password: _, ...data } = user.toJSON();

    return {
      user: data,
      token: this.getJwtToken({ id: user.id })
    }

  }

  async register(registerDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerDto);

    return {
      user,
      token: this.getJwtToken({ id: user._id })
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findOneById(id: string): Promise<User> {
    const user =  await this.userModel.findById(id);
    const { password: _, ...data } = user.toJSON();
    return data as User;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
