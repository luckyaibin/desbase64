#ifndef __DESBASE64_H__
#define __DESBASE64_H__

#include "base64.h"
#include <memory.h>

//////////////////////////////////////////////////////////////////////////
//des加密解密相关
//////////////////////////////////////////////////////////////////////////
union des_block;

//传入需要被加密的数据字节长度，获得加密后数据所需要的长度
uint32 get_des_encrypt_need_buff_size(uint32 byte_size);

//传入需要被解密的数据字节长度，获得加解密后数据所需要的长度
uint32 get_des_decrypt_need_buff_size(uint32 byte_size);

//返回加密后数据的长度
uint32 des_encrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);

//返回加密后数据的长度
uint32 des_decrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);


//////////////////////////////////////////////////////////////////////////
// data -> des->base64 -> data' -> base64 -> des -> data相关
//////////////////////////////////////////////////////////////////////////

//传入需要被加密的数据字节长度，获得des加密然后转码为base64后数据所需要的长度
uint32 get_des_base64_encrypt_need_buff_size(uint32 byte_size);

//传入需要被解码base64然后des解密的数据字节长度，获得加解密后数据所需要的长度
uint32 get_base64_des_decrypt_need_buff_size(uint32 byte_size);

//把加密后的des 转 base64编码时用的
struct des_to_base64_enc_block;

//把base64解码 然后des解密时用的
struct base64_to_des_dec_block;

//边进行des加密，边进行base64转码
//返回加密后数据的长度
uint32 des_base64_encrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);

//边进行base64解码，边des解密
//返回加密后数据的长度
uint32 base64_des_decrypt(void *void_p_output_buf,int32 output_buf_len,void* void_p_input_buf,int32 input_buf_len,uint64 key,uint64 iv);

#endif