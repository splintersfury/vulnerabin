_Cvtvec * __cdecl _Getcvt(_Cvtvec *__return_storage_ptr__)

{
  wchar_t *pwVar1;
  UINT UVar2;
  uint uVar3;
  wchar_t **ppwVar4;
  ushort *puVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  
  __return_storage_ptr__->_Page = 0;
  __return_storage_ptr__->_Mbcurmax = 0;
  __return_storage_ptr__->_Isclocale = 0;
  __return_storage_ptr__->_Isleadbyte[0] = '\0';
  __return_storage_ptr__->_Isleadbyte[1] = '\0';
  __return_storage_ptr__->_Isleadbyte[2] = '\0';
  __return_storage_ptr__->_Isleadbyte[3] = '\0';
  __return_storage_ptr__->_Isleadbyte[4] = '\0';
  __return_storage_ptr__->_Isleadbyte[5] = '\0';
  __return_storage_ptr__->_Isleadbyte[6] = '\0';
  __return_storage_ptr__->_Isleadbyte[7] = '\0';
  __return_storage_ptr__->_Isleadbyte[8] = '\0';
  __return_storage_ptr__->_Isleadbyte[9] = '\0';
  __return_storage_ptr__->_Isleadbyte[10] = '\0';
  __return_storage_ptr__->_Isleadbyte[0xb] = '\0';
  __return_storage_ptr__->_Isleadbyte[0xc] = '\0';
  __return_storage_ptr__->_Isleadbyte[0xd] = '\0';
  __return_storage_ptr__->_Isleadbyte[0xe] = '\0';
  __return_storage_ptr__->_Isleadbyte[0xf] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x10] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x11] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x12] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x13] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x14] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x15] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x16] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x17] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x18] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x19] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x1a] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x1b] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x1c] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x1d] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x1e] = '\0';
  __return_storage_ptr__->_Isleadbyte[0x1f] = '\0';
  UVar2 = ___lc_codepage_func();
  __return_storage_ptr__->_Page = UVar2;
  uVar3 = ___mb_cur_max_func();
  __return_storage_ptr__->_Mbcurmax = uVar3;
  ppwVar4 = ___lc_locale_name_func();
  uVar6 = 0;
  pwVar1 = ppwVar4[2];
  __return_storage_ptr__->_Isclocale = (uint)(pwVar1 == (wchar_t *)0x0);
  if (pwVar1 != (wchar_t *)0x0) {
    puVar5 = __pctype_func();
    uVar7 = uVar6;
    do {
      if ((short)*puVar5 < 0) {
        __return_storage_ptr__->_Isleadbyte[uVar7 >> 3] =
             __return_storage_ptr__->_Isleadbyte[uVar7 >> 3] | (byte)(1 << ((uint)uVar6 & 7));
      }
      uVar3 = (uint)uVar6 + 1;
      uVar6 = (ulonglong)uVar3;
      uVar7 = uVar7 + 1;
      puVar5 = puVar5 + 1;
    } while ((int)uVar3 < 0x100);
  }
  return __return_storage_ptr__;
}


// FUNCTION_END

// FUNCTION_START: _Wcrtomb @ 14002df1c

/* Library Function - Single Match
    _Wcrtomb
   
   Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release */