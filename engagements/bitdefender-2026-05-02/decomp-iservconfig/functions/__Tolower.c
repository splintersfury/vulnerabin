int __cdecl __Tolower(int param_1,_Ctypevec *param_2)

{
  wchar_t **ppwVar1;
  UINT _CchDest;
  int iVar2;
  ushort *puVar3;
  uint uVar4;
  LPCSTR _LpSrcStr;
  BOOL unaff_EBX;
  _locale_t _Plocinfo;
  byte local_c;
  undefined1 local_b;
  undefined1 local_8;
  undefined1 local_7;
  undefined1 local_6;
  
  if (param_2 == (_Ctypevec *)0x0) {
    ppwVar1 = ____lc_locale_name_func();
    _Plocinfo = (_locale_t)ppwVar1[2];
    _CchDest = ____lc_codepage_func();
  }
  else {
    _Plocinfo = (_locale_t)param_2->_LocaleName;
    _CchDest = param_2->_Page;
  }
  if (_Plocinfo == (_locale_t)0x0) {
    if (param_1 < 0x41) {
      return param_1;
    }
    if (0x5a < param_1) {
      return param_1;
    }
    return param_1 + 0x20;
  }
  if ((uint)param_1 < 0x100) {
    if (param_2 == (_Ctypevec *)0x0) {
      iVar2 = _isupper(param_1);
      if (iVar2 == 0) {
        return param_1;
      }
LAB_1002ce2a:
      puVar3 = ___pctype_func();
      uVar4 = puVar3[param_1 >> 8 & 0xff] & 0x8000;
      goto LAB_1002ce13;
    }
    if ((*(byte *)(param_2->_Table + param_1) & 1) == 0) {
      return param_1;
    }
  }
  else if (param_2 == (_Ctypevec *)0x0) goto LAB_1002ce2a;
  uVar4 = (uint)(int)param_2->_Table[param_1 >> 8 & 0xff] >> 0xf & 1;
LAB_1002ce13:
  if (uVar4 == 0) {
    local_7 = 0;
    _LpSrcStr = (LPCSTR)0x1;
    local_8 = (char)param_1;
  }
  else {
    local_6 = 0;
    _LpSrcStr = (LPCSTR)0x2;
    local_8 = (char)((uint)param_1 >> 8);
    local_7 = (char)param_1;
  }
  iVar2 = ___crtLCMapStringA(_Plocinfo,(LPCWSTR)0x100,(DWORD)&local_8,_LpSrcStr,(int)&local_c,
                             (LPSTR)0x3,_CchDest,1,unaff_EBX);
  if ((iVar2 != 0) && (param_1 = (int)local_c, iVar2 != 1)) {
    param_1 = (int)CONCAT11(local_c,local_b);
  }
  return param_1;
}


// FUNCTION_END

// FUNCTION_START: __Getcvt @ 1002ce8f

/* Library Function - Single Match
    __Getcvt
   
   Library: Visual Studio 2019 Release */