import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

@Schema({ timestamps: true, discriminatorKey: 'role', virtuals: true })
export class Seller {
  userName: string;
  email: string;
  password: string;

  @Prop({ type: String, required: true })
  whatsappLink: string;
}

export const sellerSchema = SchemaFactory.createForClass(Seller);
