#include "desbase64.h"
uint32 des_encrypt(char *output_buf,int32 output_buf_len,char* input_buf,int32 input_buf_len,uint64 key,uint64 iv)
{
	int32 enc_full_group_index = 0;//8�ֽ�һ�������
	int32 encrypted_byte = 0;//���ܺ����ݵ��ֽ���
	int32 full_group = input_buf_len / 8;
	int32 left_byte = input_buf_len - full_group*8;
	ubyte c0,c1,c2,c3,c4,c5,c6,c7;
	des_block block;
	while (enc_full_group_index < full_group)
	{
		block.uint64_part = 0;
		c0 = input_buf[enc_full_group_index*8];
		c1 = input_buf[enc_full_group_index*8+1];
		c2 = input_buf[enc_full_group_index*8+2];
		c3 = input_buf[enc_full_group_index*8+3];
		c4 = input_buf[enc_full_group_index*8+4];
		c5 = input_buf[enc_full_group_index*8+5];
		c6 = input_buf[enc_full_group_index*8+6];
		c7 = input_buf[enc_full_group_index*8+7];
		enc_full_group_index = enc_full_group_index + 1;
		block.ubyte_part[0] = c0;
		block.ubyte_part[1] = c1;
		block.ubyte_part[2] = c2;
		block.ubyte_part[3] = c3;
		block.ubyte_part[4] = c4;
		block.ubyte_part[5] = c5;
		block.ubyte_part[6] = c6;
		block.ubyte_part[7] = c7;

		printf("%lx\n",block.uint64_part);
		//�ó�ʼ���������һ��
		block.uint64_part ^= iv;

		uint64 encrypted_block = Des(block.uint64_part,key,'e');
		memcpy(output_buf+encrypted_byte,&encrypted_block,sizeof(uint64));
		encrypted_byte = encrypted_byte + 8;
	}
	//���ʣ���1~7�ֽ�
	if (left_byte)
	{
		block.uint64_part = 0;
		c0=c1=c2=c3=c4=c5=c6=c7=0;
		if (left_byte==1)
		{
			c0 = input_buf[enc_full_group_index*8];
		}
		else if (left_byte==2)
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
		}
		else if (left_byte==3)
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
			c2 = input_buf[enc_full_group_index*8+2];
		}
		else if (left_byte==4)
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
			c2 = input_buf[enc_full_group_index*8+2];
			c3 = input_buf[enc_full_group_index*8+3];
		}
		else if (left_byte==5)
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
			c2 = input_buf[enc_full_group_index*8+2];
			c3 = input_buf[enc_full_group_index*8+3];
			c4 = input_buf[enc_full_group_index*8+4];
		}
		else if (left_byte==6)
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
			c2 = input_buf[enc_full_group_index*8+2];
			c3 = input_buf[enc_full_group_index*8+3];
			c4 = input_buf[enc_full_group_index*8+4];
			c5 = input_buf[enc_full_group_index*8+5];
		}
		else //left_byte==7
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
			c2 = input_buf[enc_full_group_index*8+2];
			c3 = input_buf[enc_full_group_index*8+3];
			c4 = input_buf[enc_full_group_index*8+4];
			c5 = input_buf[enc_full_group_index*8+5];
			c6 = input_buf[enc_full_group_index*8+6];
		}

		block.ubyte_part[0] = c0;
		block.ubyte_part[1] = c1;
		block.ubyte_part[2] = c2;
		block.ubyte_part[3] = c3;
		block.ubyte_part[4] = c4;
		block.ubyte_part[5] = c5;
		block.ubyte_part[6] = c6;
		block.ubyte_part[7] = c7;

		printf("%lx\n",block.uint64_part);
		//�ó�ʼ���������һ��
		block.uint64_part ^= iv;

		block.uint64_part = Des(block.uint64_part,key,'e');
		memcpy(output_buf+encrypted_byte,&block.uint64_part,sizeof(uint64));
		encrypted_byte = encrypted_byte + 8;
	}
	//���д�����ݳ���
	if (input_buf_len)
	{
		block.uint64_part = input_buf_len;
		//�ó�ʼ���������һ��
		block.uint64_part ^= iv;

		block.uint64_part = Des(block.uint64_part,key,'e');
		memcpy(output_buf+encrypted_byte,&block.uint64_part,sizeof(uint64));
		encrypted_byte = encrypted_byte + 8;
	}
	return encrypted_byte;
}

uint32 des_decrypt(char *output_buf,int32 output_buf_len,char* input_buf,int32 input_buf_len,uint64 key,uint64 iv)
{
	int32 dec_full_group_index = 0;//8�ֽ�һ�������
	int32 decrypted_byte = 0;//���ܺ����ݵ��ֽ���
	int32 full_group = input_buf_len / 8;//input_buf_len ����Ӧ��Ϊ16�ֽڣ����ݿ�8�ֽ�+���ȿ�8�ֽڣ�
	ubyte c0,c1,c2,c3,c4,c5,c6,c7;
	des_block block;
	while (dec_full_group_index < full_group )
	{
		block.uint64_part = 0;
		c0 = input_buf[dec_full_group_index*8];
		c1 = input_buf[dec_full_group_index*8+1];
		c2 = input_buf[dec_full_group_index*8+2];
		c3 = input_buf[dec_full_group_index*8+3];
		c4 = input_buf[dec_full_group_index*8+4];
		c5 = input_buf[dec_full_group_index*8+5];
		c6 = input_buf[dec_full_group_index*8+6];
		c7 = input_buf[dec_full_group_index*8+7];
		dec_full_group_index = dec_full_group_index + 1;
		block.ubyte_part[0] = c0;
		block.ubyte_part[1] = c1;
		block.ubyte_part[2] = c2;
		block.ubyte_part[3] = c3;
		block.ubyte_part[4] = c4;
		block.ubyte_part[5] = c5;
		block.ubyte_part[6] = c6;
		block.ubyte_part[7] = c7;

		printf("%lx\n",block);


		block.uint64_part = Des(block.uint64_part,key,'d');
		//�ó�ʼ���������һ��
		block.uint64_part ^= iv;
		memcpy(output_buf+decrypted_byte,&block.uint64_part,sizeof(uint64));
		decrypted_byte = decrypted_byte + 8;
	}
	//���һ�����ݿ��������ʱ���ȣ�ֱ�ӷ���
	return block.uint64_part;
}

uint32 get_des_encrypt_need_buff_size(uint32 byte_size)
{
	//DES��������64bitΪһ�飬������ҪΪ8�ֽڵ�������
	uint32 des_need_byte = 0;
	uint32 des_full_group = byte_size / 8;
	if (byte_size - des_full_group*8)
		des_need_byte = des_full_group*8 + 8;
	else
		des_need_byte = des_full_group*8;

	//�����Ҫ�ٶ�һ��8�ֽ�block�����洢�����Ĵ�С
	des_need_byte=des_need_byte + 8;
	return des_need_byte;
}

uint32 get_des_decrypt_need_buff_size(uint32 byte_size)
{
	//DES��������64bitΪһ�飬������ҪΪ8�ֽڵ�������
	uint32 des_need_byte = 0;
	uint32 des_full_group = byte_size / 8;
	if (byte_size - des_full_group*8)
		des_need_byte = des_full_group*8 + 8;
	else
		des_need_byte = des_full_group*8;
	return des_need_byte;
}

uint32 des_base64_encrypt(char *output_buf,int32 output_buf_len,char* input_buf,int32 input_buf_len,uint64 key,uint64 iv)
{
	int32 enc_full_group_index = 0;//8�ֽ�һ�������
	int32 encrypted_byte = 0;//���ܺ����ݵ��ֽ���
	int32 full_group = input_buf_len / 8;
	int32 left_byte = input_buf_len - full_group*8;
	ubyte c0,c1,c2,c3,c4,c5,c6,c7;
	des_block block;

	des_to_base64_enc_block b64_block;
	b64_block.filled_index = -1;

	ubyte d = 0;
	ubyte e = 0;
	ubyte f = 0;
	ubyte g = 0;

	ubyte a = 0;
	ubyte b = 0;
	ubyte c = 0;

	while (enc_full_group_index < full_group)
	{
		block.uint64_part = 0;
		c0 = input_buf[enc_full_group_index*8];
		c1 = input_buf[enc_full_group_index*8+1];
		c2 = input_buf[enc_full_group_index*8+2];
		c3 = input_buf[enc_full_group_index*8+3];
		c4 = input_buf[enc_full_group_index*8+4];
		c5 = input_buf[enc_full_group_index*8+5];
		c6 = input_buf[enc_full_group_index*8+6];
		c7 = input_buf[enc_full_group_index*8+7];
		enc_full_group_index = enc_full_group_index + 1;
		block.ubyte_part[0] = c0;
		block.ubyte_part[1] = c1;
		block.ubyte_part[2] = c2;
		block.ubyte_part[3] = c3;
		block.ubyte_part[4] = c4;
		block.ubyte_part[5] = c5;
		block.ubyte_part[6] = c6;
		block.ubyte_part[7] = c7;

		printf("%lx\n",block.uint64_part);
		//�ó�ʼ���������һ��
		block.uint64_part ^= iv;
		block.uint64_part = Des(block.uint64_part,key,'e');

		//desһ��block֮�����������base64����
		for(int i=0;i<8;)
		{
			//�����һ������base64����������ֽ�
			while (b64_block.filled_index<2 && i<8)
			{
				b64_block.c_arr[++b64_block.filled_index] = block.ubyte_part[i++];
			}
			//�������
			if (b64_block.filled_index==2)
			{
				b64_block.filled_index = -1;
				a = b64_block.c_arr[0];
				b =  b64_block.c_arr[1];
				c =  b64_block.c_arr[2];

				d = a >> 2;
				e = ((a & 0x3)<<4) | (b>>4);
				f = ((b&0xF)<<2) | (c>>6) ;
				g = c & 0x3F;
				output_buf[encrypted_byte++] = charset[d];
				output_buf[encrypted_byte++] = charset[e];
				output_buf[encrypted_byte++] = charset[f];
				output_buf[encrypted_byte++] = charset[g]; 
			}
		}
	}
	//���ʣ���1~7�ֽ�
	if (left_byte)
	{
		block.uint64_part = 0;
		c0=c1=c2=c3=c4=c5=c6=c7=0;
		if (left_byte==1)
		{
			c0 = input_buf[enc_full_group_index*8];
		}
		else if (left_byte==2)
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
		}
		else if (left_byte==3)
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
			c2 = input_buf[enc_full_group_index*8+2];
		}
		else if (left_byte==4)
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
			c2 = input_buf[enc_full_group_index*8+2];
			c3 = input_buf[enc_full_group_index*8+3];
		}
		else if (left_byte==5)
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
			c2 = input_buf[enc_full_group_index*8+2];
			c3 = input_buf[enc_full_group_index*8+3];
			c4 = input_buf[enc_full_group_index*8+4];
		}
		else if (left_byte==6)
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
			c2 = input_buf[enc_full_group_index*8+2];
			c3 = input_buf[enc_full_group_index*8+3];
			c4 = input_buf[enc_full_group_index*8+4];
			c5 = input_buf[enc_full_group_index*8+5];
		}
		else //left_byte==7
		{
			c0 = input_buf[enc_full_group_index*8];
			c1 = input_buf[enc_full_group_index*8+1];
			c2 = input_buf[enc_full_group_index*8+2];
			c3 = input_buf[enc_full_group_index*8+3];
			c4 = input_buf[enc_full_group_index*8+4];
			c5 = input_buf[enc_full_group_index*8+5];
			c6 = input_buf[enc_full_group_index*8+6];
		}

		block.ubyte_part[0] = c0;
		block.ubyte_part[1] = c1;
		block.ubyte_part[2] = c2;
		block.ubyte_part[3] = c3;
		block.ubyte_part[4] = c4;
		block.ubyte_part[5] = c5;
		block.ubyte_part[6] = c6;
		block.ubyte_part[7] = c7;

		printf("%lx\n",block.uint64_part);
		//�ó�ʼ���������һ��
		block.uint64_part ^= iv;

		block.uint64_part = Des(block.uint64_part,key,'e');
		
		//desһ��block֮�����������base64����
		for(int i=0;i<8;)
		{
			//�����һ������base64����������ֽ�
			while (b64_block.filled_index<2 && i<8)
			{
				b64_block.c_arr[++b64_block.filled_index] = block.ubyte_part[i++];
			}
			//�������
			if (b64_block.filled_index==2)
			{
				b64_block.filled_index = -1;
				a =  b64_block.c_arr[0];
				b =  b64_block.c_arr[1];
				c =  b64_block.c_arr[2];

				d = a >> 2;
				e = ((a & 0x3)<<4) | (b>>4);
				f = ((b&0xF)<<2) | (c>>6) ;
				g = c & 0x3F;
				output_buf[encrypted_byte++] = charset[d];
				output_buf[encrypted_byte++] = charset[e];
				output_buf[encrypted_byte++] = charset[f];
				output_buf[encrypted_byte++] = charset[g]; 
			}
		}
	}
	//���д�����ݳ���
	if (input_buf_len)
	{
		block.uint64_part = input_buf_len;
		//�ó�ʼ���������һ��
		block.uint64_part ^= iv;

		block.uint64_part = Des(block.uint64_part,key,'e');
		//desһ��block֮�����������base64����
		for(int i=0;i<8;)
		{
			//�����һ������base64����������ֽ�
			while (b64_block.filled_index<2 && i<8)
			{
				b64_block.c_arr[++b64_block.filled_index] = block.ubyte_part[i++];
			}
			//�������
			if (b64_block.filled_index==2)
			{
				b64_block.filled_index = -1;
				a =  b64_block.c_arr[0];
				b =  b64_block.c_arr[1];
				c =  b64_block.c_arr[2];

				d = a >> 2;
				e = ((a & 0x3)<<4) | (b>>4);
				f = ((b&0xF)<<2) | (c>>6) ;
				g = c & 0x3F;
				output_buf[encrypted_byte++] = charset[d];
				output_buf[encrypted_byte++] = charset[e];
				output_buf[encrypted_byte++] = charset[f];
				output_buf[encrypted_byte++] = charset[g]; 
			}
		}
	}
	//���������������ϳ�������base64��������
	if (b64_block.filled_index != -1)
	{
		a = b64_block.c_arr[0];
		b = 0;
		c = 0;
		d=e=f=g=0;
		//ȱ�������ֽ�����
		if (b64_block.filled_index == 0)
		{
			b = 0;
			c = 0;

			d = a >> 2;
			e = ((a & 0x3)<<4) | (b>>4);
			f = 64;// = ���Ⱥ�
			g = 64;// =
		}
		//ȱ��һ���ֽ�����
		if (b64_block.filled_index == 1)
		{
			b =  b64_block.c_arr[1];
			c = 0;
			d = a >> 2;
			e = ((a & 0x3)<<4) | (b>>4);
			f = ((b&0xf)<<2) | (c>>6) ; ;
			g = 64;
		}
		//printf("%c,%c,%c,%c\n",charset[d],charset[e],charset[f],charset[g]);
		output_buf[encrypted_byte++] = charset[d];
		output_buf[encrypted_byte++] = charset[e];
		output_buf[encrypted_byte++] = charset[f];
		output_buf[encrypted_byte++] = charset[g];
	}
	return encrypted_byte;
}

uint32 base64_des_decrypt(char *output_buf,int32 output_buf_len,char* input_buf,int32 input_buf_len,uint64 key,uint64 iv)
{
	int32 out_index = 0;
	int32 curr_index = 0;
	int32 last_char_index =  4 * (input_buf_len / 4);//�ĸ�һ������һ��char������
	int32 left_char_num = input_buf_len - last_char_index;//ʣ��Ĳ����ĸ�һ���char��������ֻ��Ϊ1��2��3
	if(left_char_num)
	{
		return 0;//�����ʣ���ֽڵĻ���˵�������⵽���ƻ������ݱ����base64֮��һ����4�ֽڵı������������޷�ȡ��des����ʱ��������һ��4�ֽ������ԭʼ�ļ��ĳ���
	}
	int32 decrypted_byte = 0;
	ubyte d = 0;
	ubyte e = 0;
	ubyte f = 0;
	ubyte g = 0;

	ubyte a = 0;
	ubyte b = 0;
	ubyte c = 0;

	base64_to_des_dec_block bdb;
	 bdb.des_b.uint64_part = 0;
	bdb.filled_index = -1;
	while (curr_index < last_char_index)
	{
		d = input_buf[curr_index];
		e = input_buf[curr_index+1];
		f = input_buf[curr_index+2];
		g = input_buf[curr_index+3];
		curr_index = curr_index + 4;

		d = reverse_charset[d];
		e = reverse_charset[e];
		f = reverse_charset[f];
		g = reverse_charset[g];

		a = ((d & 0x3F)<<2)| ( (e>>4) & 0x3);
		b = ((e & 0xF)<<4) | ( (f>>2) & 0xF);
		c = ((f & 0x3)<<6) | (	g & 0x3F);

		//printf("%d,%d,%d,%d\n",d,e,f,g);
		//printf("%c,%c,%c,%c\n",charset[d],charset[e],charset[f],charset[g]);


		if(bdb.filled_index<7)
		{
			bdb.des_b.ubyte_part[++bdb.filled_index] = a;
		}
		if (bdb.filled_index==7)//�������һ������des���ܵĵ�Ԫ
		{
			bdb.filled_index = -1;
			bdb.des_b.uint64_part = Des(bdb.des_b.uint64_part,key,'d');
			//�ó�ʼ���������һ��
			bdb.des_b.uint64_part ^= iv;
			memcpy(output_buf+decrypted_byte,&bdb.des_b.uint64_part,sizeof(uint64));
			decrypted_byte = decrypted_byte + 8;
		}


		if(bdb.filled_index<7)
		{
			bdb.des_b.ubyte_part[++bdb.filled_index] = b;
		}
		if (bdb.filled_index==7)//�������һ������des���ܵĵ�Ԫ
		{
			bdb.filled_index = -1;
			bdb.des_b.uint64_part = Des(bdb.des_b.uint64_part,key,'d');
			//�ó�ʼ���������һ��
			bdb.des_b.uint64_part ^= iv;
			memcpy(output_buf+decrypted_byte,&bdb.des_b.uint64_part,sizeof(uint64));
			decrypted_byte = decrypted_byte + 8;
		}


		if(bdb.filled_index<7)
		{
			bdb.des_b.ubyte_part[++bdb.filled_index] = c;
		}
		if (bdb.filled_index==7)//�������һ������des���ܵĵ�Ԫ
		{
			bdb.filled_index = -1;
			bdb.des_b.uint64_part = Des(bdb.des_b.uint64_part,key,'d');
			//�ó�ʼ���������һ��
			bdb.des_b.uint64_part ^= iv;
			memcpy(output_buf+decrypted_byte,&bdb.des_b.uint64_part,sizeof(uint64));
			decrypted_byte = decrypted_byte + 8;
		}
	}
	if (bdb.filled_index != -1)
	{
		return 0;
	}

	//����ԭʼ���ݵĳ���
	return bdb.des_b.uint64_part;
}

uint32 get_des_base64_encrypt_need_buff_size(uint32 byte_size)
{
	//DES��������64bitΪһ�飬������ҪΪ8�ֽڵ�������
	uint32 des_need_byte = 0;
	uint32 des_full_group = byte_size / 8;
	if (byte_size - des_full_group*8)
		des_need_byte = des_full_group*8 + 8;
	else
		des_need_byte = des_full_group*8;

	//�����Ҫ�ٶ�һ��8�ֽ�block�����洢�����Ĵ�С
	des_need_byte=des_need_byte + 8;
	uint32 base64_need_byte = get_base64_encode_need_buf_len(des_need_byte);
	return base64_need_byte;
}

uint32 get_base64_des_decrypt_need_buff_size(uint32 byte_size)
{
	uint32 base64_need_byte = get_base64_decode_need_buf_len(byte_size);
	//DES��������64bitΪһ�飬������ҪΪ8�ֽڵ�������
	uint32 des_need_byte = 0;
	uint32 des_full_group = base64_need_byte / 8;
	if (base64_need_byte - des_full_group*8)
		des_need_byte = des_full_group*8 + 8;
	else
		des_need_byte = des_full_group*8;

	return des_need_byte;
}

