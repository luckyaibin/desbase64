#ifndef __BASE64_H__
#define __BASE64_H__
#include "base_type.h"

#include <stdio.h>

// Global variable.
// Note: To change the charset to a URL encoding, replace the '+' and '/' with '*' and '-'
extern ubyte charset[66];

extern uint32 reverse_charset[255];

//��ñ�����������С�����С
int32 get_base64_encode_need_buf_len(int32 in_buf_len);

//base64���룬out������Ҫ�㹻��,encode64���ر��������ݳ���
int32 encode64(char * out_buf,int32 out_buf_len,char * in_buf,int32 in_buf_len);

int32 get_base64_decode_need_buf_len(int32 in_buf_len);

//���ؽ��������ݳ���
int32 decode64(char * out_buf,int32 out_buf_len,char * in_buf,int32 in_buf_len);

#endif