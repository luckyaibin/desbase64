#ifndef __DESBASE64_H__
#define __DESBASE64_H__
#include "des.h"
#include "base64.h"
#include <memory.h>

//////////////////////////////////////////////////////////////////////////
//des���ܽ������
//////////////////////////////////////////////////////////////////////////

//������Ҫ�����ܵ������ֽڳ��ȣ���ü��ܺ���������Ҫ�ĳ���
uint32 get_des_encrypt_need_buff_size(uint32 byte_size);

//������Ҫ�����ܵ������ֽڳ��ȣ���üӽ��ܺ���������Ҫ�ĳ���
uint32 get_des_decrypt_need_buff_size(uint32 byte_size);

union des_block
{
	ubyte ubyte_part[8];
	uint64 uint64_part;
};

//���ؼ��ܺ����ݵĳ���
uint32 des_encrypt(char *output_buf,int32 output_buf_len,char* input_buf,int32 input_buf_len,uint64 key,uint64 iv);

//���ؼ��ܺ����ݵĳ���
uint32 des_decrypt(char *output_buf,int32 output_buf_len,char* input_buf,int32 input_buf_len,uint64 key,uint64 iv);



//////////////////////////////////////////////////////////////////////////
// data -> des->base64 -> data' -> base64 -> des -> data���
//////////////////////////////////////////////////////////////////////////

//������Ҫ�����ܵ������ֽڳ��ȣ����des����Ȼ��ת��Ϊbase64����������Ҫ�ĳ���
uint32 get_des_base64_encrypt_need_buff_size(uint32 byte_size);

//������Ҫ������base64Ȼ��des���ܵ������ֽڳ��ȣ���üӽ��ܺ���������Ҫ�ĳ���
uint32 get_base64_des_decrypt_need_buff_size(uint32 byte_size);


//�Ѽ��ܺ��des ת base64����ʱ�õ�
struct des_to_base64_enc_block
{
	ubyte c_arr[3];
	char  filled_index;//filled��ʾ���d����c_arr�ڼ���ubyte��0��1��2,-1��ʾһ����û���
};

//��base64���� Ȼ��des����ʱ�õ�
struct base64_to_des_dec_block
{
	des_block des_b;
	char  filled_index;//filled��ʾ���d����des_b.ubyte_part�ڼ���ubyte��0��1��2,3��4��5��6��7. -1��ʾһ����û���
};


//�߽���des���ܣ��߽���base64ת��
//���ؼ��ܺ����ݵĳ���
uint32 des_base64_encrypt(char *output_buf,int32 output_buf_len,char* input_buf,int32 input_buf_len,uint64 key,uint64 iv);

//�߽���base64���룬��des����
//���ؼ��ܺ����ݵĳ���
uint32 base64_des_decrypt(char *output_buf,int32 output_buf_len,char* input_buf,int32 input_buf_len,uint64 key,uint64 iv);

#endif