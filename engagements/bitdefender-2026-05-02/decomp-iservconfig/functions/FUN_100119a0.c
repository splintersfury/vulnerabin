void __fastcall FUN_100119a0(int *param_1)

{
  int iVar1;
  size_t sVar2;
  size_t _Count;
  int local_2c;
  undefined1 local_28 [32];
  uint local_8;
  
  local_8 = DAT_10069054 ^ (uint)&stack0xfffffffc;
  if ((param_1[0xe] == 0) || (*(char *)((int)param_1 + 0x3d) == '\0')) {
    FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  iVar1 = (**(code **)(*param_1 + 0xc))(0xffffffff);
  if (iVar1 != -1) {
    iVar1 = (**(code **)(*(int *)param_1[0xe] + 0x20))(param_1 + 0x10,local_28,&local_8,&local_2c);
    if (iVar1 == 0) {
      *(undefined1 *)((int)param_1 + 0x3d) = 0;
    }
    else if (iVar1 != 1) {
      if (iVar1 == 3) {
        *(undefined1 *)((int)param_1 + 0x3d) = 0;
        FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
      goto LAB_10011a4a;
    }
    _Count = local_2c - (int)local_28;
    if (_Count != 0) {
      sVar2 = _fwrite(local_28,1,_Count,(FILE *)param_1[0x13]);
      if (_Count != sVar2) goto LAB_10011a4a;
    }
    FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
LAB_10011a4a:
  FUN_1002e315(local_8 ^ (uint)&stack0xfffffffc);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10011a70 @ 10011a70