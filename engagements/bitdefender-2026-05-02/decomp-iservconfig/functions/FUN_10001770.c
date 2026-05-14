void FUN_10001770(void)

{
  undefined4 local_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined8 uStack_30;
  DWORD local_1c;
  undefined **local_18;
  uint local_14;
  
  local_14 = DAT_10069054 ^ (uint)&local_40;
  local_1c = 0;
  local_18 = &PTR_vftable_10069aa8;
  FUN_1001daa0(&local_40,&local_1c);
  DAT_1006b690 = local_40;
  uRam1006b694 = uStack_3c;
  uRam1006b698 = uStack_38;
  uRam1006b69c = uStack_34;
  _DAT_1006b6a0 = uStack_30;
  _atexit((_func_4879 *)&LAB_10050f40);
  FUN_1002e315(local_14 ^ (uint)&local_40);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_10001840 @ 10001840