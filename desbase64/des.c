
/////////////////////////////des.cpp
#include"des.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//void Dump(uint32 i)
//{
//	std::string bits;
//	for (int p=1;p<=32;p++)
//	{
//		char c = GET_BIT32(i,p) + '0';
//		bits += c;
//		int tmp = ( (p-1) % 4) + 1;
//		if (  tmp == 4 )
//		{
//			bits += " ";
//		}
//	}
//	printf("%s\n",bits.c_str());
//	printf("0x%x\n",i);
//}

//void Dump(uint64 i)
//{
//	std::string bits;
//	for (int p=1;p<=64;p++)
//	{
//	char c = GET_BIT64(i,p) + '0';
//	bits += c;
//	int tmp = ( (p-1) % 4) + 1;
//	if (  tmp == 4 )
//	{
//	bits += " ";
//	}
//	}
//	printf("%s\n",bits.c_str());
//	printf("0x%llx\n",i);
//}

//初始置换
void ApplyIP(uint64* data)
{
	uint64 _data = 0;
	int i = 0;
	for (i=1;i<=64;i++)
	{
		//printf("把第%d设置为第%d位的%d",i,IP[i-1],GET_BIT64(data,IP[i-1]));
		SET_BIT64(_data,i,GET_BIT64(*data,IP[i-1]));
	}
	*data = _data;
}

void ApplyFP(uint64* data)
{
	uint64 _data = 0;
	int i=0;
	for (i=1;i<=64;i++)
	{
		SET_BIT64(_data,i,GET_BIT64(*data,FP[i-1]));
	}
	*data = _data;
}

uint64 g_subkeys[16] = {0};

void GenerateSubKeys(uint64 *subkeys,uint64 key)
{
	//秘钥置换，从64位取出56位
	uint64 key56 = 0;
	int i=0;
	for (i=9;i<=64;i++)
	{
		SET_BIT64(key56,i,GET_BIT64(key, KPT[i-9]));
	}
	//key = key56;

	for (i=1;i<=16;i++)
	{
		int j=0;
		uint32 C1 = 0;
		uint32 C2 = 0;
		uint64 one_sub_key = 0;
		//把两个28bit的部分循环左移一定位数
		CYC_LEFT_SHIFT(key56,9,36,LST[i-1]);
		CYC_LEFT_SHIFT(key56,37,64,LST[i-1]);

		
		GET_BIT_RANGE64(C1,key56,9,36);
		GET_BIT_RANGE64(C2,key56,37,64);
		//std::cout<<TO_STR(CYC_LEFT_SHIFT(key56,9,36,LST[i-1]));
		//std::cout<<"-----------" <<std::endl;
		//std::cout<<TO_STR(CYC_LEFT_SHIFT(key56,9,36,LST[i-1]));

		//从56个bit中选出48个bit（压缩），作为第 i 个子秘钥
		
		for (j=17;j<=64;j++)
		{
			int pos_in_bit64 = 8 + CPT[j-17];
			SET_BIT64(one_sub_key,j,GET_BIT64(key56,pos_in_bit64));   
		}
		*(subkeys + i-1) = one_sub_key;
	}     
}

uint64 ExpandData(uint32 data)
{
	uint64 expanded_data = 0;
	int i=0;
	for (i=1;i<=48;i++)
	{
		SET_BIT64(expanded_data,i+16,GET_BIT32(data,EPT[i-1]));
	}
	return expanded_data;
}


uint32 S_Box(uint64 xor_data)
{
#define MASK_SIX_BITS 0x3F
#define MASK_FOUR_BITS 0x0F   
#define MASK_ONE_BITS 0x02
	uint32 s_box_result = 0;
	//xor_data 是异或后的48位数据
	uint32 line = 0;
	uint32 column = 0;
	uint32 s_box_data_1 = 0;
	int i=0;
	uint32 v=0;
	//8个s box,for 循环
	for (i=0;i<8;i++)
	{
		s_box_data_1 = 0;
		s_box_data_1 = (xor_data >> (6*(7-i)))& MASK_SIX_BITS;
		line = 0;
		column = 0;

		line = ((s_box_data_1 >>4)&MASK_ONE_BITS) | (s_box_data_1 & 1);
		column = (s_box_data_1>>1) & MASK_FOUR_BITS;
		//左移四位，空出4个bit
		s_box_result = s_box_result<<4;

		v = S_Boxes[i][line][column];

		//printf("用%x替换后为",v);
		s_box_result |= v;
	}   
	//std::cout<<"S-Box替换后为"<<std::endl;
	return s_box_result;
}


uint32 P_Box(uint32 s_box_result)
{
	//P 置换
	uint32 p_result = 0;
	int i=0;
	for (i=1;i<=32;i++)
	{
		int idx = P[i-1];
		uint32 v = GET_BIT32(s_box_result,idx);
		SET_BIT32(p_result,i,v);
	}
	return p_result;
}


uint32 Apply_f(uint32 _R,int round)
{
	uint64 expanded_R = 0;
	uint64 sub_key=0;
	uint64 xor_result = 0;
	uint32 s_box_result = 0;
	uint32 p_box_result = 0;
	expanded_R = ExpandData(_R);

	sub_key = g_subkeys[round];

	xor_result = expanded_R ^ sub_key;

	s_box_result = S_Box(xor_result);

	p_box_result = P_Box(s_box_result);
	return p_box_result;
}


uint64 Des(uint64 _data,uint64 _key,char en_or_de)
{
	static uint64 inited_sub_keys = 0;
	uint64 data = _data;
	uint64 key = _key;
	uint32 L0 = 0;
	uint32 R0 = 0;
	int round = 0;
	//key不同的话，要重新初始化子密钥
	if ( _key != inited_sub_keys)
	{
		GenerateSubKeys(g_subkeys,key);
		inited_sub_keys = _key;
	}
	ApplyIP(&data);
	L0 = data>>32;
	R0 = (uint32)data;

	for (round =0;round<=15;round++)
	{
		uint32 round_by_en_or_de;
		uint32 p_box_result = 0;
		if (en_or_de=='e')
			round_by_en_or_de = round;
		else if(en_or_de=='d')
			round_by_en_or_de = 15-round;
		else
			return 0;

		p_box_result = Apply_f(R0,round_by_en_or_de);
		// 第一轮的 p_box_result 应为: D61AC5A2
		if (round!=15)
		{
			//交换
			uint32 tmp = R0;
			R0 = L0 ^p_box_result;
			L0 = tmp;
		}
		else //round == 15，是最后一轮，不交换L 和R
		{
			L0 = L0 ^p_box_result;
		}   
	}
	data = (uint64)L0<<32 | R0;
	ApplyFP(&data);
	return data;
}