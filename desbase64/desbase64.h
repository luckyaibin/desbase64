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
//des加密解密相关
//////////////////////////////////////////////////////////////////////////

//传入需要被加密的数据字节长度，获得加密后数据所需要缓存的最小长度
uint32 DLL_API __cdecl get_des_encrypt_need_buff_size(uint32 byte_size);

//传入需要被解密的数据字节长度，获得加解密后数据所需要缓存的最小长度
uint32 DLL_API __cdecl get_des_decrypt_need_buff_size(uint32 byte_size);


/************************************************************************/
/* des加密：返回加密后数据的长度
void_p_output_buf:输出缓冲，大小要调用者使用get_des_encrypt_need_buff_size 来确定大小后分配
output_buf_len:输出缓存大小
void_p_input_buf:需要被加密的数据
input_buf_len：需要被加密的数据的长度（字节)
key:DES 密钥
iv: 初始化向量，加密和解密的时候要用相同的iv                                                                     */
/************************************************************************/
uint32 DLL_API __cdecl des_encrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);

//返回加密后数据的长度
uint32 DLL_API __cdecl des_decrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);


//////////////////////////////////////////////////////////////////////////
// data -> des->base64 -> data' -> base64 -> des -> data相关
//////////////////////////////////////////////////////////////////////////

//传入需要被加密的数据字节长度，获得des加密然后转码为base64后数据所需要的长度
uint32 DLL_API __cdecl get_des_base64_encrypt_need_buff_size(uint32 byte_size);

//传入需要被解码base64然后des解密的数据字节长度，获得加解密后数据所需要的长度
uint32 DLL_API __cdecl get_base64_des_decrypt_need_buff_size(uint32 byte_size);

//边进行des加密，边进行base64转码
//返回加密后数据的长度
//key:DES 密钥
//iv: 初始化向量，加密和解密的时候要用相同的iv
uint32 DLL_API __cdecl des_base64_encrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);

//边进行base64解码，边des解密
//返回加密后数据的长度
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