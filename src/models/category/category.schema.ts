import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { SchemaTypes, Types } from 'mongoose';

@Schema({ timestamps: true })
export class Category {
  readonly _id: Types.ObjectId;
  @Prop({ type: String, required: true, unique: true, trim: true })
  name: string;
  @Prop({ type: String, required: true, unique: true, trim: true })
  slug: string;
  @Prop({ type: SchemaTypes.ObjectId, ref: 'Admin', required: true })
  createdBy: Types.ObjectId;
}

export const categorySchema = SchemaFactory.createForClass(Category);
