#ifndef __DESBASE64_H__
#define __DESBASE64_H__
#include "des.h"
#include "base64.h"
#include <memory.h>

//������Ҫ�����ܵ������ֽڳ��ȣ���ü��ܺ���������Ҫ�ĳ���
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

//������Ҫ�����ܵ������ֽڳ��ȣ���üӽ��ܺ���������Ҫ�ĳ���
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


//������Ҫ�����ܵ������ֽڳ��ȣ���ü��ܺ���������Ҫ�ĳ���
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

//������Ҫ�����ܵ������ֽڳ��ȣ���üӽ��ܺ���������Ҫ�ĳ���
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


union des_block
{
	ubyte ubyte_part[8];
	uint64 uint64_part;
};

//���ؼ��ܺ����ݵĳ���
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

		uint64 encrypted_block = Des(block.uint64_part,key,'e');
		memcpy(output_buf+encrypted_byte,&encrypted_block,sizeof(uint64));
		encrypted_byte = encrypted_byte + 8;
	}
	//���д�����ݳ���
	if (input_buf_len)
	{
		block.uint64_part = input_buf_len;
		//�ó�ʼ���������һ��
		block.uint64_part ^= iv;

		uint64 encrypted_block = Des(block.uint64_part,key,'e');
		memcpy(output_buf+encrypted_byte,&encrypted_block,sizeof(uint64));
		encrypted_byte = encrypted_byte + 8;
	}
	return encrypted_byte;
}

//���ؼ��ܺ����ݵĳ���
uint32 des_decrypt(char *output_buf,int32 output_buf_len,char* input_buf,int32 input_buf_len,uint64 key,uint64 iv)
{
	int32 dec_full_group_index = 0;//8�ֽ�һ�������
	int32 decrypted_byte = 0;//���ܺ����ݵ��ֽ���
	int32 full_group = input_buf_len / 8;//input_buf_len ����Ӧ��Ϊ16�ֽڣ����ݿ�8�ֽ�+���ȿ�8�ֽڣ�
	ubyte c0,c1,c2,c3,c4,c5,c6,c7;
	des_block block;
	uint64 decrypted_block = 0;
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
		

		decrypted_block = Des(block.uint64_part,key,'d');
		//�ó�ʼ���������һ��
		decrypted_block ^= iv;
		memcpy(output_buf+decrypted_byte,&decrypted_block,sizeof(uint64));
		decrypted_byte = decrypted_byte + 8;
	}
	//���һ�����ݿ��������ʱ���ȣ�ֱ�ӷ���
	 return decrypted_block;
}

#endif