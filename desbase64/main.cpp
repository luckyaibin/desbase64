/////////////main.cpp
#include "des.h"
#include <iostream>

int main()
{
	uint64 data = 0x77616E6777616E77;//wangwanw;
	uint64 key = 0x77616E6777616E61;//wangwana

	uint64 res= Des(data,key,'e');// 0xC4DF68A1853AE96F

	uint64 res2 = Des(res,key,'d');
	system("pause");
	return 0;
}