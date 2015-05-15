#ifndef __DESBASE64_H__
#define __DESBASE64_H__

#include "base64.h"
#include <memory.h>

//////////////////////////////////////////////////////////////////////////
//des���ܽ������
//////////////////////////////////////////////////////////////////////////
union des_block;

//������Ҫ�����ܵ������ֽڳ��ȣ���ü��ܺ���������Ҫ�ĳ���
uint32 get_des_encrypt_need_buff_size(uint32 byte_size);

//������Ҫ�����ܵ������ֽڳ��ȣ���üӽ��ܺ���������Ҫ�ĳ���
uint32 get_des_decrypt_need_buff_size(uint32 byte_size);

//���ؼ��ܺ����ݵĳ���
uint32 des_encrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);

//���ؼ��ܺ����ݵĳ���
uint32 des_decrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);


//////////////////////////////////////////////////////////////////////////
// data -> des->base64 -> data' -> base64 -> des -> data���
//////////////////////////////////////////////////////////////////////////

//������Ҫ�����ܵ������ֽڳ��ȣ����des����Ȼ��ת��Ϊbase64����������Ҫ�ĳ���
uint32 get_des_base64_encrypt_need_buff_size(uint32 byte_size);

//������Ҫ������base64Ȼ��des���ܵ������ֽڳ��ȣ���üӽ��ܺ���������Ҫ�ĳ���
uint32 get_base64_des_decrypt_need_buff_size(uint32 byte_size);

//�Ѽ��ܺ��des ת base64����ʱ�õ�
struct des_to_base64_enc_block;

//��base64���� Ȼ��des����ʱ�õ�
struct base64_to_des_dec_block;

//�߽���des���ܣ��߽���base64ת��
//���ؼ��ܺ����ݵĳ���
uint32 des_base64_encrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);

//�߽���base64���룬��des����
//���ؼ��ܺ����ݵĳ���
uint32 base64_des_decrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);

#endif