#ifndef __DESBASE64_H__
#define __DESBASE64_H__
#include "base_type.h"
#ifdef DLL_DES_BASE64_IMPLEMENT
	#define DLL_API __declspec(dllexport)
#else
	#define DLL_API __declspec(dllimport)
#endif

#include <memory.h>

//////////////////////////////////////////////////////////////////////////
//des���ܽ������
//////////////////////////////////////////////////////////////////////////

//������Ҫ�����ܵ������ֽڳ��ȣ���ü��ܺ���������Ҫ�������С����
uint32 DLL_API __cdecl get_des_encrypt_need_buff_size(uint32 byte_size);

//������Ҫ�����ܵ������ֽڳ��ȣ���üӽ��ܺ���������Ҫ�������С����
uint32 DLL_API __cdecl get_des_decrypt_need_buff_size(uint32 byte_size);


/************************************************************************/
/* des���ܣ����ؼ��ܺ����ݵĳ���
void_p_output_buf:������壬��СҪ������ʹ��get_des_encrypt_need_buff_size ��ȷ����С�����
output_buf_len:��������С
void_p_input_buf:��Ҫ�����ܵ�����
input_buf_len����Ҫ�����ܵ����ݵĳ��ȣ��ֽ�)
key:DES ��Կ
iv: ��ʼ�����������ܺͽ��ܵ�ʱ��Ҫ����ͬ��iv                                                                     */
/************************************************************************/
uint32 DLL_API __cdecl des_encrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);

//���ؼ��ܺ����ݵĳ���
uint32 DLL_API __cdecl des_decrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);


//////////////////////////////////////////////////////////////////////////
// data -> des->base64 -> data' -> base64 -> des -> data���
//////////////////////////////////////////////////////////////////////////

//������Ҫ�����ܵ������ֽڳ��ȣ����des����Ȼ��ת��Ϊbase64����������Ҫ�ĳ���
uint32 DLL_API __cdecl get_des_base64_encrypt_need_buff_size(uint32 byte_size);

//������Ҫ������base64Ȼ��des���ܵ������ֽڳ��ȣ���üӽ��ܺ���������Ҫ�ĳ���
uint32 DLL_API __cdecl get_base64_des_decrypt_need_buff_size(uint32 byte_size);

//�߽���des���ܣ��߽���base64ת��
//���ؼ��ܺ����ݵĳ���
//key:DES ��Կ
//iv: ��ʼ�����������ܺͽ��ܵ�ʱ��Ҫ����ͬ��iv
uint32 DLL_API __cdecl des_base64_encrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);

//�߽���base64���룬��des����
//���ؼ��ܺ����ݵĳ���
uint32 DLL_API __cdecl base64_des_decrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);


/////////////////////////////////////////////////////////
typedef uint32  (__cdecl *fn_type_get_des_encrypt_need_buff_size)(uint32);
typedef uint32  (__cdecl *fn_type_get_des_decrypt_need_buff_size)(uint32); 
typedef uint32  (__cdecl *fn_type_des_encrypt)(void *,int32,void*,int32,uint64,uint64); 
typedef uint32  (__cdecl *fn_type_des_decrypt)(void *,int32,void*,int32,uint64,uint64);

typedef uint32  (__cdecl *fn_type_get_des_base64_encrypt_need_buff_size)(uint32); 
typedef uint32  (__cdecl *fn_type_get_base64_des_decrypt_need_buff_size)(uint32); 
typedef uint32  (__cdecl *fn_type_des_base64_encrypt)(void *,int32,void*,int32,uint64,uint64);
typedef uint32  (__cdecl *fn_type_base64_des_decrypt)(void *,int32,void*,int32,uint64,uint64);

#endif