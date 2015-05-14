#ifndef __BASE64_H__
#define __BASE64_H__
#include "base_type.h"

#include <stdio.h>

// Global variable.
// Note: To change the charset to a URL encoding, replace the '+' and '/' with '*' and '-'
extern ubyte charset[66];

extern uint32 reverse_charset[255];

//获得编码后所需的最小缓冲大小
int32 get_base64_encode_need_buf_len(int32 in_buf_len);

//base64编码，out缓冲需要足够大,encode64返回编码后的数据长度
int32 encode64(char * out_buf,int32 out_buf_len,char * in_buf,int32 in_buf_len);

int32 get_base64_decode_need_buf_len(int32 in_buf_len);

//返回解码后的数据长度
int32 decode64(char * out_buf,int32 out_buf_len,char * in_buf,int32 in_buf_len);

#endif