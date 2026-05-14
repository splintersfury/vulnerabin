void FUN_14001d7d0(longlong *param_1)

{
  int iVar1;
  undefined1 auStack_68 [32];
  longlong *local_48;
  longlong local_38;
  undefined1 local_30 [32];
  ulonglong local_10;
  
  local_10 = DAT_14007a060 ^ (ulonglong)auStack_68;
  if ((param_1[0xd] == 0) || (*(char *)((longlong)param_1 + 0x71) == '\0')) {
    FUN_14002f160(local_10 ^ (ulonglong)auStack_68);
    return;
  }
  iVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)(param_1,0xffffffff);
  if (iVar1 != -1) {
    local_48 = &local_38;
    iVar1 = (*(code *)PTR__guard_dispatch_icall_14005b538)
                      (param_1[0xd],(longlong)param_1 + 0x74,local_30,&local_10);
    if (iVar1 == 0) {
      *(undefined1 *)((longlong)param_1 + 0x71) = 0;
    }
    else if (iVar1 != 1) {
      if (iVar1 == 3) {
        *(undefined1 *)((longlong)param_1 + 0x71) = 0;
      }
      goto LAB_14001d85a;
    }
    if (local_38 - (longlong)local_30 != 0) {
      fwrite(local_30,1,local_38 - (longlong)local_30,(FILE *)param_1[0x10]);
    }
  }
LAB_14001d85a:
  FUN_14002f160(local_10 ^ (ulonglong)auStack_68);
  return;
}


// FUNCTION_END

// FUNCTION_START: FUN_14001d8d0 @ 14001d8d0