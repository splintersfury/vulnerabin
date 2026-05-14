void __fastcall FUN_10007e90(int *param_1)

{
  int iVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_1004e010;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_8 = 0;
  iVar1 = *(int *)(*param_1 + 4);
  if ((*(int *)(iVar1 + 0xc + (int)param_1) == 0) &&
     ((*(byte *)(iVar1 + 0x14 + (int)param_1) & 2) != 0)) {
    iVar1 = (**(code **)(**(int **)(iVar1 + 0x38 + (int)param_1) + 0x34))();
    if (iVar1 == -1) {
      FUN_10002bd0((void *)(*(int *)(*param_1 + 4) + (int)param_1),
                   *(uint *)(*(int *)(*param_1 + 4) + 0xc + (int)param_1) | 4,'\0');
    }
  }
  ExceptionList = local_10;
  return;
}


// FUNCTION_END

// FUNCTION_START: Catch_All@10007f0b @ 10007f0b