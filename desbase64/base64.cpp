#include "base64.h"


ubyte charset[]={"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="};

uint32 reverse_charset[255] = {
	0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 0 ~ 14
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 15 ~ 29
	0,0,0,0,0,0,0,0,0,0,0,0,62,0,0,// 30 ~ 44
	0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,//45 ~ 59
	64,0,0,0,0,1,2,3,4,5,6,7,8,9,10,	//60 ~ 74
	11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,//75 ~ 89
	0,0,0,0,0,0,26,27,28,29,30,31,32,33,34,
	35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,
	50,51,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};

int32 get_base64_encode_need_buf_len(int32 in_buf_len)
{
	int32 full_group = (in_buf_len/3);
	if ( in_buf_len - full_group * 3)
		return full_group*4 + 4;
	else
		return full_group*4;
}

int32 encode64(char * out_buf,int32 out_buf_len,char * in_buf,int32 in_buf_len)
{
	int32 out_index = 0;
	int32 curr_index = 0;
	int32 last_char_index =  3 * (in_buf_len / 3);//三个一组的最后一个char的索引
	int32 left_char_num = in_buf_len - last_char_index;//剩余的不够三个一组的char的数量，只能为1或2

	char a = 0;
	char b = 0;
	char c = 0;

	char d = 0;
	char e = 0;
	char f = 0;
	char g = 0;
	while (curr_index < last_char_index)
	{
		a = in_buf[curr_index];
		b = in_buf[curr_index+1];
		c = in_buf[curr_index+2];
		curr_index = curr_index + 3;

		d = a >> 2;
		e = ((a & 0x3)<<4) | (b>>4);
		f = ((b&0xF)<<2) | (c>>6) ;
		g = c & 0x3F;
		//printf("%d,%d,%d,%d\n",d,e,f,g);
		//printf("%c,%c,%c,%c\n",charset[d],charset[e],charset[f],charset[g]);
		if (out_index < out_buf_len)
			out_buf[out_index++] = charset[d];
		else
			break;
		if (out_index < out_buf_len)
			out_buf[out_index++] = charset[e];
		else
			break;
		if (out_index < out_buf_len)
			out_buf[out_index++] = charset[f];
		else
			break;
		if (out_index < out_buf_len)
			out_buf[out_index++] = charset[g];
		else
			break;
	}
	//处理结尾剩余字节
	if(left_char_num)
	{
		a = in_buf[curr_index];
		if (left_char_num == 1)
		{
			b = 0;
			c = 0;

			d = a >> 2;
			e = ((a & 0x3)<<4) | (b>>4);
			f = 64 ;
			g = 64;
		}
		if (left_char_num == 2)
		{
			b = in_buf[curr_index+1];
			c = 0;
			d = a >> 2;
			e = ((a & 0x3)<<4) | (b>>4);
			f = ((b&0xf)<<2) | (c>>6) ; ;
			g = 64;
		}
		//printf("%c,%c,%c,%c\n",charset[d],charset[e],charset[f],charset[g]);
		if (out_index < out_buf_len)
			out_buf[out_index++] = charset[d];
		if (out_index < out_buf_len)
			out_buf[out_index++] = charset[e];
		if (out_index < out_buf_len)
			out_buf[out_index++] = charset[f];
		if (out_index < out_buf_len)
			out_buf[out_index++] = charset[g];
	}
	return out_index;//返回的是编码后的长度
}

int32 get_base64_decode_need_buf_len(int32 in_buf_len)
{
	int32 full_group = (in_buf_len/4);
	if (in_buf_len - full_group*4)//某些情况下出错的时候，编码之后的字符串并不是正好为4的整数倍
		return full_group*3 + 3;
	return full_group*3;
}

int32 decode64(char * out_buf,int32 out_buf_len,char * in_buf,int32 in_buf_len)
{
	int32 out_index = 0;
	int32 curr_index = 0;
	int32 last_char_index =  4 * (in_buf_len / 4);//四个一组的最后一个char的索引
	int32 left_char_num = in_buf_len - last_char_index;//剩余的不够四个一组的char的数量，只能为1或2或3
	ubyte d = 0;
	ubyte e = 0;
	ubyte f = 0;
	ubyte g = 0;

	ubyte a = 0;
	ubyte b = 0;
	ubyte c = 0;


	while (curr_index < last_char_index)
	{
		d = in_buf[curr_index];
		e = in_buf[curr_index+1];
		f = in_buf[curr_index+2];
		g = in_buf[curr_index+3];
		curr_index = curr_index + 4;

		d = reverse_charset[d];
		e = reverse_charset[e];
		f = reverse_charset[f];
		g = reverse_charset[g];

		a = ((d & 0x3F)<<2)| ( (e>>4) & 0x3);
		b = ((e & 0xF)<<4) | ( (f>>2) & 0xF);
		c = ((f & 0x3)<<6) | (	g & 0x3F);

		//printf("%d,%d,%d,%d\n",d,e,f,g);
		//printf("%c,%c,%c,%c\n",charset[d],charset[e],charset[f],charset[g]);
		if (out_index < out_buf_len)
			out_buf[out_index++] = a;
		else
			break;
		if (out_index < out_buf_len)
			out_buf[out_index++] = b;
		else
			break;
		if (out_index < out_buf_len)
			out_buf[out_index++] = c;
		else
			break;
	}
	//处理结尾剩余字节
	if(left_char_num)
	{
		d = in_buf[curr_index];
		if (left_char_num == 3)
		{
			e = in_buf[curr_index+1];
			f = in_buf[curr_index+2];
			g = 0;

			d = reverse_charset[d];
			e = reverse_charset[e];
			f = reverse_charset[f];
			g = reverse_charset[g];

			a = ((d & 0x3F)<<2)| ( (e>>4) & 0x3);
			b = ((e & 0xF)<<4) | ( (f>>2) & 0xF);
			c = ((f & 0x3)<<6) | (	g & 0x3F);
			//printf("%c,%c,%c,%c\n",charset[d],charset[e],charset[f],charset[g]);
			if (out_index < out_buf_len)
				out_buf[out_index++] = a;
			if (out_index < out_buf_len)
				out_buf[out_index++] = b;
			if (out_index < out_buf_len)
				out_buf[out_index++] = c;

		}
		if (left_char_num == 2)
		{
			e = in_buf[curr_index+1];
			f = 0;
			g = 0;
			d = reverse_charset[d];
			e = reverse_charset[e];
			f = reverse_charset[f];
			g = reverse_charset[g];

			a = ((d & 0x3F)<<2)| ( (e>>4) & 0x3);
			b = ((e & 0xF)<<4) | ( (f>>2) & 0xF);
			//printf("%c,%c,%c,%c\n",charset[d],charset[e],charset[f],charset[g]);
			if (out_index < out_buf_len)
				out_buf[out_index++] = a;
			if (out_index < out_buf_len)
				out_buf[out_index++] = b;
		}
		if (left_char_num == 1)
		{
			e = 0;
			f = 0;
			g = 0;

			d = reverse_charset[d];
			e = reverse_charset[e];
			f = reverse_charset[f];
			g = reverse_charset[g];

			a = ((d & 0x3F)<<2)| ( (e>>4) & 0x3);
			if (out_index < out_buf_len)
				out_buf[out_index++] = a;
		}		
	}
	return out_index;//返回的是编码后的长度
}
