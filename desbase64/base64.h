#ifndef __BASE64_H__
#define __BASE64_H__
#include "base_type.h"

#include <stdio.h>

// Global variable.
// Note: To change the charset to a URL encoding, replace the '+' and '/' with '*' and '-'
ubyte charset[]={"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};
 
int32_t encode64(char * out,char * in,int32_t in_len)
{
	//�����ֽ���һ�飬�ж��ٸ���
	int32_t group_num = in_len / 3;
	//ʣ����ٸ��ֽڣ�ֵ����1����2
	int32_t left_num = in_len % 3;
	

	//���ָ��Ϊ��ʱ�����ر�������Ļ����С
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