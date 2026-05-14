int __cdecl
_Mbrtowc(wchar_t *param_1,char *param_2,size_t param_3,mbstate_t *param_4,_Cvtvec *param_5)

{
  ulong *puVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  byte *pbVar5;
  
  if (param_3 == 0) {
    return 0;
  }
  if (*param_2 == '\0') {
    *param_1 = L'\0';
    return 0;
  }
  if (param_5->_Isclocale == 0) {
    uVar2 = param_5->_Mbcurmax;
    if (uVar2 != 1) {
      if (uVar2 == 2) {
        if ((param_5->_Isleadbyte[(byte)*param_2 >> 3] & (byte)(1 << (*param_2 & 7U))) == 0) {
          iVar3 = 1;
        }
        else {
          if (param_3 == 1) {
            return -2;
          }
          iVar3 = 2;
        }
        iVar4 = MultiByteToWideChar(param_5->_Page,9,param_2,iVar3,param_1,1);
        if (iVar4 != 0) {
          return iVar3;
        }
        goto LAB_14002e105;
      }
      iVar3 = 2;
      if (uVar2 == 4) {
        if (*param_2 < '\0') {
          if ((*param_2 & 0xe0U) == 0xc0) {
            iVar3 = 1;
            uVar2 = (byte)*param_2 & 0x1f;
          }
          else {
            if ((*param_2 & 0xf0U) != 0xe0) goto LAB_14002e105;
            uVar2 = (byte)*param_2 & 0xf;
          }
          iVar4 = 1;
          pbVar5 = (byte *)(param_2 + 1);
          do {
            if (param_3 <= (ulonglong)(longlong)iVar4) {
              return -2;
            }
            if ((*pbVar5 & 0xc0) != 0x80) goto LAB_14002e105;
            iVar4 = iVar4 + 1;
            uVar2 = *pbVar5 & 0x3f | uVar2 << 6;
            pbVar5 = pbVar5 + 1;
            iVar3 = iVar3 + -1;
          } while (iVar3 != 0);
          if (0x7ff < uVar2 - 0xd800) {
            *param_1 = (wchar_t)uVar2;
            return iVar4;
          }
          goto LAB_14002e105;
        }
        goto LAB_14002e115;
      }
    }
    iVar3 = MultiByteToWideChar(param_5->_Page,9,param_2,1,param_1,1);
    if (iVar3 == 0) {
LAB_14002e105:
      puVar1 = __doserrno();
      *puVar1 = 0x2a;
      return -1;
    }
  }
  else {
LAB_14002e115:
    *param_1 = (ushort)(byte)*param_2;
  }
  return 1;
}


// FUNCTION_END

// FUNCTION_START: _Getwctype @ 14002e134

/* Library Function - Single Match
    _Getwctype
   
   Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release */