void FUN_10029990(void *param_1,int *param_2,wchar_t *param_3)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  wchar_t *_Str2;
  int *local_34;
  short local_30 [8];
  int local_20;
  undefined **local_1c;
  uint local_18;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1005090d;
  local_10 = ExceptionList;
  uVar2 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_20 = 0;
  local_1c = &PTR_vftable_10069aa8;
  local_18 = uVar2;
  FUN_100280a0(local_30,param_1,param_2,&local_20,&local_20);
  local_8 = 0;
  if ((local_1c[1] == DAT_10069aac) && (local_20 == 0)) {
    piVar3 = (int *)FUN_10027a20(&local_34,local_30);
    if ((undefined4 *)*piVar3 == (undefined4 *)0x0) {
      _Str2 = (wchar_t *)0x0;
    }
    else {
      _Str2 = *(wchar_t **)*piVar3;
    }
    __wcsicmp(param_3,_Str2);
    if (local_34 != (int *)0x0) {
      LOCK();
      piVar3 = local_34 + 2;
      iVar1 = *piVar3;
      *piVar3 = *piVar3 + -1;
      UNLOCK();
      if ((iVar1 == 1) && (local_34 != (int *)0x0)) {
        if (*local_34 != 0) {
          Ordinal_6(*local_34,uVar2);
          *local_34 = 0;
        }
        if ((void *)local_34[1] != (void *)0x0) {
          thunk_FUN_100330ca((void *)local_34[1]);
          local_34[1] = 0;
        }
        FUN_1002e346(local_34);
      }
      local_34 = (int *)0x0;
    }
  }
  Ordinal_9(local_30);
  ExceptionList = local_10;
  FUN_1002e315(local_18 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10029ab0 @ 10029ab0