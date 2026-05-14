void __thiscall
FUN_10002ad0(void *this,wchar_t *param_1,wchar_t *param_2,char param_3,char *param_4)

{
  int iVar1;
  char cVar2;
  mbstate_t local_18 [2];
  char local_10 [8];
  uint local_8;
  
  local_8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  if (param_1 != param_2) {
    do {
      local_18[0] = 0;
      local_18[1] = 0;
      iVar1 = __Wcrtomb(local_10,*param_1,local_18,(_Cvtvec *)((int)this + 0x18));
      cVar2 = local_10[0];
      if (iVar1 != 1) {
        cVar2 = param_3;
      }
      param_1 = param_1 + 1;
      *param_4 = cVar2;
      param_4 = param_4 + 1;
    } while (param_1 != param_2);
  }
  FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10002b50 @ 10002b50