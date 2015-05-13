#ifndef __BASE64_H__
#define __BASE64_H__
#include "base_type.h"

#include <stdio.h>

// Global variable.
// Note: To change the charset to a URL encoding, replace the '+' and '/' with '*' and '-'
ubyte charset[]={"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};
 
int32_t encode64(char * out,char * in,int32_t in_len)
{
	//三个字节算一组，有多少个组
	int32_t group_num = in_len / 3;
	//剩余多少个字节，值不是1就是2
	int32_t left_num = in_len % 3;
	

	//输出指针为空时，返回编码所需的缓冲大小
	if (!out)
	{
		
		left_byte = in_len*3 + ( (in_len - n*3)>0 ? 3 : 0 );
		return n;
	}
	
	output_group o;
	o.a = in->a.h;
	o.
}

#endif